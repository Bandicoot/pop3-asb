/*
 * pop3 sample implementation 
 * with mbox format mail files
 * 
 * this program is called by inetd(8) as such: pop3   stream  tcp     nowait
 * root    /usr/local/libexec/pop3asb pop3asb
 * 
 * Copyright 2004, Andrew Scott Beals
 * 
 */

#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>		/* getpwent() and friends */
#include <unistd.h>		/* crypt() */
#include <string.h>		/* strdup() */
#include <fcntl.h>		/* open modes */
#include <sys/stat.h>
#include <sys/mman.h>		/* mmap */
#include <stdlib.h>		/* malloc */
#include <sys/param.h>		/* MAXLOGNAME */
#include <md4.h>
#include <md5.h>
#include <gdbm.h>
#include <syslog.h>
#include <stdarg.h>

#include "pop3.h"

struct command  Transactions[] = {
    {"top", 2, pop3_top,},	/* show top N lines of a message */
    {"uidl", -1, pop3_uidl,},	/* list unique ids */
    {"stat", 0, pop3_stat,},
    {"list", -1, pop3_list,},
    {"retr", 1, pop3_retr,},
    {"dele", 1, pop3_dele,},
    {"noop", 0, pop3_noop,},
    {"rset", 0, pop3_rset,},
    {"quit", 0, pop3_quit,},	/* ciao */
    {NULL, 0, NULL},
};

struct command  Authorization[] = {
    {"apop", 2, pop3_apop,},	/* secure authentication */
    {"user", 1, pop3_user,},	/* who are you? */
    {"quit", 0, pop3_quit,},	/* ciao */
    {NULL, 0, NULL},
};


/*
 * RFC1939 says that PASS may be given only immediately following a
 * successful USER command
 * 
 */
struct command  User_Chosen[] = {
    {"pass", 1, pop3_pass,},	/* password */
    {"quit", 0, pop3_quit,},	/* ciao */
    {NULL, 0, NULL},
};

struct command *commands = Authorization;	/* which commands are valid
						 * now */
struct message *messages;

char            mbox_file[2*BUFSIZ] = {'\0',};
int             mbox_fd = -1;
char           *mbox_region = NULL;	/* mmap'ed mbox file */
size_t          mbox_size = 0;
int             num_messages = 0;

static char    *user = NULL;	/* who are you? */
static struct passwd *user_pw = NULL;	/* passwd file entry */

char            apop_secret[2*BUFSIZ];

void 
response_ok(char *resp)
{
    printf("+OK %s\r\n", resp);
}


void 
response_bad(char *resp)
{
    printf("-ERR %s\r\n", resp);
}


int 
pop3_top(char *msg, char *lines)
{
    int             msgno, nlines;
    struct message *m;
    char           *p;

    msgno = atoi(msg) - 1;
    if ((msgno < 0) || (msgno >= num_messages)) {
	response_bad("message number out of range");
	return BAD;
    }
    nlines = atoi(lines);
    if (nlines < 1) {
	response_bad("we have a comedian here - must specify a positive number of lines");
	return BAD;
    }
    for (m = messages; m; m = m->next, msgno--) {
	if (msgno == 0)
	    break;		/* found it */
    }
    /* m can't be null here */
    if (m == NULL) {
	response_bad("can't get here from there");
	return BAD;
    }
    if (m->stat == DELETED) {
	response_bad("I won't do that for a deleted message");
	return BAD;
    }
    /* find the extent of the header: */
    for (p = m->message;; p++) {
	if ((*p == '\n') && (p[1] == '\n')) {	/* at end of header */
	    p++;
	    break;
	}
    }

    /* now start counting lines: */
    for (++p; p <= (m->message + m->length); p++) {
	if (*p == '\n') {
	    nlines--;
	    if (nlines == 0)
		break;
	}
    }
    /* up to first N lines or EOM whichever is first */

    response_ok("");
    net_output(m->message, p - m->message + 1);
    printf(".\r\n");

    return OK;
}


/*
 * use the "fast" md4 calculation
 * 
 * cucipop skips "Content-Length", "Status" and "X-Status" headers but since I
 * don't modify the message, it doesn't matter
 * 
 */
char           *
uidl(unsigned char *buf, unsigned length)
{
    int             i;
    MD4_CTX         md4[1];
    unsigned char   digest[16];
    static char     output[1 + 2 * sizeof digest];	/* ASCIIfied hex */
    char           *p;

    MD4Init(md4);
    MD4Update(md4, buf, length);
    MD4Final(digest, md4);

    for (i = 0, p = output; i < sizeof digest; i++, p += 2) {
	sprintf(p, "%02x", digest[i]);
    }

    return output;
}


int 
pop3_uidl(char *msg)
{
    char            buf[2*BUFSIZ];
    struct message *m;
    int             mess, i;

    if (*msg == '\0') {
	response_ok("");

	for (i = 0, m = messages; i < num_messages; i++, m = m->next) {
	    if (m->stat == DELETED)
		continue;
	    printf("%u %s\r\n", i + 1, uidl(m->message, m->length));
	}
	printf(".\r\n");
	return OK;
    }
    mess = atoi(msg);
    if ((mess < 1) || ((mess - 1) >= num_messages)) {
	response_bad("invalid message number");
	return BAD;
    }
    mess--;

    for (i = 0, m = messages; m; i++, m = m->next) {
	if (i != mess)
	    continue;
	if (m->stat == DELETED) {
	    response_bad("I can't do that for a deleted message");
	    return BAD;
	}
	sprintf(buf, "%u %s", i + 1, uidl(m->message, m->length));
	response_ok(buf);
	return OK;
    }

    response_bad("no such message - this shouldn't happen");
    return BAD;
}

int 
pop3_stat()
{
    char            mail_info[2*BUFSIZ];

    sprintf(mail_info, "%u %u", num_messages, mbox_size);

    response_ok(mail_info);
    return OK;
}

int 
pop3_list(char *msg)
{
    struct message *m;
    unsigned        msgno = 0;
    char            buf[2*BUFSIZ];

    if (*msg == '\0') {
	sprintf(buf, "%u message%s (%u octets)", num_messages, num_messages > 1 ? "s" : "", mbox_size);
	response_ok(buf);
	if (num_messages) {
	    msgno++;
	    for (m = messages; m; m = m->next, msgno++) {
		if (m->stat == DELETED)
		    continue;
		printf("%d %u\r\n", msgno, m->length);
	    }
	}
	printf(".\r\n");
	return OK;
    }
    msgno = atoi(msg);
    if (msgno == 0) {
	response_bad("message numbers start at 1");
	return BAD;
    }
    msgno--;
    if (msgno >= num_messages) {
	response_bad("no such message");
	return BAD;
    }
    for (m = messages; msgno--; m = m->next);

    if (m->stat == DELETED) {
	response_bad("message deleted");
	return BAD;
    }
    sprintf(buf, "%s %u", msg, m->length);
    response_ok(buf);

    return OK;
}


net_output(char *p, unsigned len)
{
    for (; len; len--, p++) {
	if (*p == '\n') {
	    putchar('\r');
	    putchar('\n');
	    if (p[1] == '.')
		putchar('.');
	} else {
	    putchar(*p);
	}
    }
}


int 
pop3_retr(char *msg)
{
    unsigned        msgno;
    struct message *m;
    char            buf[2*BUFSIZ];

    if (!strcmp(msg, "0")) {
	response_bad("message 0 is not a valid message number");
	return BAD;
    }
    msgno = atoi(msg) - 1;
    if (msgno >= num_messages) {
	response_bad("no such message, kimosabe");
	return BAD;
    }
    for (m = messages; msgno--; m = m->next);

    if (m->stat == DELETED) {
	response_bad("that message is no more");
	return BAD;
    }
    sprintf(buf, "%u octets", m->length);
    response_ok(buf);
    net_output(m->message, m->length);
    printf(".\r\n");
}

int 
pop3_dele(char *msg)
{
    int             msgno;
    struct message *m;

    if (!strcmp(msg, "0")) {
	response_bad("message 0 is not a valid message number");
	return BAD;
    }
    msgno = atoi(msg) - 1;
    if (msgno >= num_messages) {
	response_bad("no such message, kimosabe");
	return BAD;
    }
    for (m = messages; msgno--; m = m->next);

    if (m->stat == DELETED) {
	response_bad("that message is no more");
	return BAD;
    }
    m->stat = DELETED;

    response_ok("the message disappears");

    return OK;
}


int 
pop3_noop()
{
    response_ok("Nothing happens");
    return OK;

}


int 
pop3_rset()
{
    struct message *m;

    for (m = messages; m; m = m->next)
	m->stat = SAVED;

    response_ok("Your mailbox feels heavier.");
    return OK;
}


int 
pop3_quit()
{
    struct message *m;
    size_t          final_length = 0;
    char           *ptr;
    char            copying = FALSE;

    response_ok("ciao for now");

    if (pop_state == AUTHORIZATION)
	exit(0);		/* nothing to do */

    pop_state = UPDATE;		/* completeness sake RFC1939 */

    ptr = messages->message;

    for (m = messages; m; m = m->next) {
	if (m->stat == DELETED) {
	    copying = 1;
	    continue;
	}
	if (copying) {
	    memcpy(ptr, m->message, m->length);
	}
	final_length += m->length;
	ptr += m->length;
    }

    if (copying) {
	ftruncate(mbox_fd, final_length);
    }
    close(mbox_fd);
    /* FIX: update mailbox here, handle deletions, new mail, etc */

    exit(0);
    return OK;			/* NOTREACHED */
}

int 
pop3_pass(char *passwd)
{
    char           *encrypted;

    if (user_pw == NULL) {
	response_bad("please identify");
	return BAD;
    }
    encrypted = crypt(passwd, user_pw->pw_passwd);

    if (strcmp(encrypted, user_pw->pw_passwd)) {
	response_bad("sorry charlie");
	return BAD;
    }
    sprintf(mbox_file, MBOX_FMT, user);
    mbox_fd = open(mbox_file, O_RDWR | O_EXLOCK);
    if (mbox_fd == -1) {
	response_bad("couldn't open and lock mbox");
	return BAD;
    }
    if (parse_mail()) {
	response_ok("oh, why didn't you say so?");

	pop_state = TRANSACTION;/* next line makes this redundant, but we're
				 * following the RFC */
	commands = Transactions;

	return OK;
    } else {
	response_bad("an error has occurred");
	return BAD;
    }
}


#define APOP_ERROR "sorry chap, don't know how to do that"

int 
pop3_apop(char *user, char *secret)
{
    MD5_CTX         md5[1];
    unsigned char   digest[16];
    datum           key, stuff;
    GDBM_FILE       dbf;
    char            buf[2*BUFSIZ];
    char            seekrit[1 + 2 * sizeof digest], *p;
    int             i;

    dbf = gdbm_open(APOP_SECRETS, 512, GDBM_READER, 0666, NULL);
    if (dbf == NULL) {
	response_bad(APOP_ERROR " guv");
	syslog(LOG_EMERG, "Can't open %s for reading", APOP_SECRETS);
	return BAD;
    }
    key.dptr = user;
    key.dsize = 1 + strlen(user);

    stuff = gdbm_fetch(dbf, key);
    if (stuff.dptr == NULL) {	/* couldn't find that key */
	syslog(LOG_NOTICE, "Can't find user %s in %s", user, APOP_SECRETS);
	response_bad(APOP_ERROR " matey");
	return BAD;
    }
    if ((stuff.dptr[stuff.dsize] != '\0') || (stuff.dsize != 1 + strlen(stuff.dptr))) {
	syslog(LOG_CRIT, "Malformed record in database %s at user %s", APOP_SECRETS, user);
	response_bad(APOP_ERROR " blokie");	/* malformed record */
	return BAD;
    }
    /* stuff.dptr is now the string with the secret */

    sprintf(buf, "%s%s", apop_secret, stuff.dptr);

    MD5Init(md5);
    MD5Update(md5, buf, strlen(buf));
    MD5Final(digest, md5);

    for (i = 0, p = seekrit; i < sizeof digest; i++, p += 2) {
	sprintf(p, "%02x", digest[i]);
    }

    if (strcmp(seekrit, secret)) {
	syslog(LOG_NOTICE, "user %s: secret %s didn't match digest %s", user, secret, seekrit);
	response_bad(APOP_ERROR);
	return BAD;
    }
    sprintf(mbox_file, MBOX_FMT, user);
    mbox_fd = open(mbox_file, O_RDWR | O_EXLOCK);
    if (mbox_fd == -1) {
	syslog(LOG_CRIT, "Error %m can't open %s", mbox_file);
	response_bad("couldn't open and lock mbox");
	return BAD;
    }
    if (parse_mail()) {
	response_ok("oh, why didn't you say so?");

	pop_state = TRANSACTION;/* next line makes this redundant, but we're
				 * following the RFC */
	commands = Transactions;

	return OK;
    } else {
	syslog(LOG_NOTICE, "coudln't parse user %s's mail file", user);
	response_bad("an error has occurred");
	return BAD;
    }
}


/*
 * map in mbox, find messages
 * 
 * ignore Content-Length: header for now
 * 
 */
int 
parse_mail()
{
    struct stat     sb[1];
    char           *msg;
    struct message *m;

    if (fstat(mbox_fd, sb) == -1) {
	syslog(LOG_NOTICE, "can't fstat the already-open mbox file");
	goto unwind;
    }
    mbox_size = sb->st_size;

    mbox_region = mmap(NULL, mbox_size, PROT_WRITE | PROT_READ, MAP_SHARED, mbox_fd, 0);

    if (mbox_region == NULL) {
	syslog(LOG_NOTICE, "can't mmap the open mbox file");
	goto unwind;
    }
    m = messages = malloc(sizeof *messages);
    if (m == NULL)
	goto unwind;		/* no RAM? - syslog */
    messages->next = NULL;
    messages->stat = SAVED;
    messages->message = mbox_region;

    if (mbox_size == 0) {	/* special-case this for speed and
				 * correctness */
	messages->length = 0;
	return TRUE;
    }
    for (msg = mbox_region; msg < (mbox_region + mbox_size);) {
	for (; *msg != '\n'; msg++);	/* point at EOL */
	if (!strncmp("From ", msg + 1, 5)) {	/* at start of message */
	    ++msg;
	    m->length = msg - m->message;
	    m->next = malloc(sizeof *m);
	    m = m->next;
	    if (m == NULL) {
		syslog(LOG_NOTICE, "malloc failed");
		goto unwind;
	    }
	    m->message = msg;
	    m->next = NULL;
	    m->stat = SAVED;
	    m->length = 0;	/* sanity */
	} else {
	    msg++;
	}
    }
    m->length = msg - m->message;
    m->stat = SAVED;

    for (m = messages; m; m = m->next) {
	num_messages++;
    }

    return TRUE;

unwind:
    close(mbox_fd);
    mbox_fd = -1;

    if (mbox_region)
	munmap(mbox_region, mbox_size);

    mbox_region = NULL;
    mbox_size = 0;

    return FALSE;
}


int 
pop3_user(char *username)
{
    if (strlen(username) + 1 > MAXLOGNAME) {
	response_bad("no such user");
    }
    user = strdup(username);
    if (user == NULL) {
	response_bad("out of RAM");
	return BAD;
    }
    /* fetch password info */

    user_pw = getpwnam(user);
    if (user_pw == NULL) {
	response_ok("nice to meet you, partner");
	return BAD;		/* FIX: ???: fake positive response here -
				 * don't give away the farm */
    }
    endpwent();

    response_ok("nice to meet you, partner");

    commands = User_Chosen;

    return OK;
}

main(int argc, char **argv)
{
    char            command[BUFSIZ], line[BUFSIZ], hostname[MAXHOSTNAMELEN];
    struct command *c;


    gethostname(hostname, sizeof hostname);
    sprintf(apop_secret, "<%u.%lu@%s>", getpid(), time(NULL), hostname);

    sprintf(line, "POP3 server ready, implementation by bandy@cinnamon.com %s", apop_secret);
    response_ok(line);

    do {
	char            arg1[BUFSIZ], arg2[BUFSIZ], junk[BUFSIZ];
	char            optional;
	unsigned int    len;
	int             numargs;
	int		nconversions;

	fflush(stdout);
	junk[0] = line[0] = command[0] = arg1[0] = arg2[0] = '\0';
	optional = FALSE;

	/* nb: fgets() zero-terminates the string */
	if (fgets(line, sizeof line - 1, stdin) == NULL) {
	    /* EOF */
	    /* don't update mbox */
	    exit(1);
	}
	len = strlen(line);
	if (len == 0) {
	    response_bad("try again");
	    continue;
	}

	if (line[len-1] != '\n') {
	    if ((line[len-2] != '\r') || (line[len-1] != '\n')) {
		response_bad("line too long");
		continue;
	    }
	    line[len-2] = '\0';
	} else {
	    line[len-1] = '\0';
	}

	/* FIX: check for junk on end of line */
	/* FIX: perhaps sscanf for all our strings at once? */
	nconversions = sscanf(line, "%s %s %s %s", command, arg1, arg2, junk);

	if (nconversions == 0) {
	    response_bad("no command?");
	    continue;
	}
	nconversions--;

	for (c = commands; c->cmd; c++) {
	    if (!strcasecmp(c->cmd, command))
		break;
	}

	if (c->cmd == NULL) {
	    response_bad("unimplemented command");
	    continue;
	}
	if (c->numargs == 0) {
	    if (c->subr() == BAD)
		syslog(LOG_NOTICE, "command %s failed", c->cmd);
	    continue;
	}
	numargs = c->numargs;

	if (numargs < 0) {
	    optional = TRUE;
	    numargs *= -1;
	}

	if (!optional) {
	    if (numargs < nconversions) {
		response_bad("syntax error - too many arguments");
		continue;
	    }
	    if (numargs > nconversions) {
		response_bad("syntax error - too few arguments");
		continue;
	    }
	}

	if (c->subr(arg1, arg2) == BAD) {
	    syslog(LOG_NOTICE, "command %s failed", c->cmd);
	}
    } while (1);
}
