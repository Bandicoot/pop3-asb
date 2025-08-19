/*
 * headerfile for Andrew Beals' pop3 program
 * 
 */

/* constants you might want to change: */

#define MBOX_FMT	"/var/mail/%s"
#define	APOP_SECRETS	"/etc/mail/apop.db"

/* you shouldn't need to change anything after this line: */

enum {
    AUTHORIZATION, TRANSACTION, UPDATE
}               pop_state = AUTHORIZATION;

#define	ONLY_TRANS  "this command is only valid in the TRANSACTION state."
#define	UNIMP	    "sorry, this command is unimplemented in this release."

#define	OK  (0)
#define	BAD (!OK)
#define	TRUE	(1==1)
#define	FALSE	(!TRUE)
#define	CLENGTH	"Content-Length: "
#define	STATUS	"Status: "
#define	XSTATUS	"X-Status: "

extern int      pop3_top(char *msg, char *nlines);
extern int      pop3_uidl(char *msg);
extern int      pop3_stat(void);
extern int      pop3_list(char *msg);
extern int      pop3_retr(char *msg);
extern int      pop3_dele(char *msg);
extern int      pop3_noop(void);
extern int      pop3_rset(void);
extern int      pop3_quit(void);
extern int      pop3_pass(char *passwd);
extern int      pop3_apop(char *user, char *seekrit);
extern int      pop3_user(char *name);

struct command {
    char           *cmd;
    int             numargs;	/* negative indicates optional */
    int             (*subr) ();
};

typedef enum {
    SAVED = 0, DELETED
}               status;

struct message {
    struct message *next;
    char           *message;
    status          stat;
    size_t          length;
};
