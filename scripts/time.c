#include <time.h>
#include <stdio.h>

void timestamp()
{
    time_t ltime; /* calendar time */
    ltime=time(NULL); /* get current cal time */
    printf("%s",asctime( localtime(&ltime) ) );
}

#define STATIC_MESG_SIZE 256
#define TIMESTAMP_FMT "%d%b%Y %T%Z"

#define make_timestamp() \
    ({ \
     char __ts[STATIC_MESG_SIZE]={0}; \
	 char *__timestamp_fmt = TIMESTAMP_FMT; \
	 const time_t __tstamp = time(NULL); \
	 strftime(__ts, STATIC_MESG_SIZE-1, \
			 __timestamp_fmt, localtime(&__tstamp)); \
     __ts; \
     })

#define trace(fmt, ...) \
    fprintf(stderr, \
    "%s %s[%d]:"#fmt"\n" \
    , make_timestamp(), __func__, __LINE__, ##__VA_ARGS__ \
    )

int main()
{
	trace("%s %d", "hello, world", 42);
	return 0;
}
