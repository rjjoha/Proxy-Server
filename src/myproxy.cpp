#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <signal.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdexcept>
#include <fstream>
#include <array>
#include <sstream>
#include <cstring>
#include <string.h>
#include <vector>
#include <regex.h>
#include <time.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

#define MAXLINE     8192
#define BUFFSIZE    8192
#define SERV_PORT   9877
#define LISTENQ     1024
#define SA          struct sockaddr

typedef struct thread_struct {
    char*   f_file;
    char*   a_file;
    int     cfd;
}Thread_struct;


pthread_mutex_t lock;

int find_server(char serv_name[], int port) {
    
    int                 n, s_sockfd;
    struct addrinfo     *address_list;
    struct addrinfo     *temp;
    char                addr_port_str[6];

    if((s_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Sock error\n");
        exit(1);
    }

    sprintf(addr_port_str, "%d", port);

    if((n = getaddrinfo(serv_name, addr_port_str, NULL, &address_list)) != 0) {
        perror("No address info exists for this server.\n");
        exit(1);
    }

    for(temp = address_list; temp; temp = temp->ai_next) {
        if((temp->ai_family == AF_INET)) {
            if(connect(s_sockfd, temp->ai_addr, temp->ai_addrlen) == 0) {
                break;
            }
        }
    }

    freeaddrinfo(address_list);
    if(!temp) {
        perror("No address info found for this address\n");
        close(s_sockfd);
        exit(1);
    }

    return s_sockfd;
}

void *proxy_thread(void *param) {
    Thread_struct *t_struct = (Thread_struct*) param;
    pthread_detach(pthread_self());

    printf("Server online\n");

    int             n, serverfd, port;
    char            recvline[MAXLINE + 1];
    char            http_request[MAXLINE];
    char            method[MAXLINE];
    char            url[MAXLINE];
    char            temp[MAXLINE];
    char            ver_type[MAXLINE];
    char            path[MAXLINE];
    char            host[MAXLINE];
    char            status[MAXLINE];
    char            *temp_path;
    char            *temp_status;
    char            *s_to_char;
    char            time_buf[80];
    time_t          rawtime;
    struct tm       *my_time;

    vector<string>  forbidden_sites;
    string          line;
    ifstream        for_file;
    ofstream        acc_file;

    time(&rawtime);
    my_time = localtime(&rawtime);
    strftime(time_buf, 80, "%Y-%m-%dT%X ", my_time);

    pthread_mutex_lock(&lock);
    for_file.open(t_struct->f_file);

    if(!for_file.is_open()) {
        perror("Issue opening file.\n");
        exit(1);
    }
    else {
        while(getline(for_file, line)) {
            forbidden_sites.push_back(line);
        }
    }
    pthread_mutex_unlock(&lock);


    if((n = read(t_struct->cfd, recvline, MAXLINE)) > 0) {
        recvline[n] = 0;
        if(fputs(recvline, stdout) == EOF) {
            perror("Fputs error\n");
            exit(1);
        }
        sscanf(recvline, "%s %s %s", method, url, ver_type);
    }

    sscanf(recvline, "%s %s %s", method, url, ver_type);

    printf("%s %s %s\n", method, url, ver_type);

    if(strcasecmp(method, "GET") && strcasecmp(method, "POST")) {
        perror("Error Code 501. Not implemented");
        exit(1);
    }

    printf("%s\n", url);

    if(strcasecmp(url, "/ ")) {
        printf("Find host\n");
        if((temp_path = strstr(recvline, "http://")) != NULL) {
            printf("Curl object\n");
            sscanf(temp_path, "http://%[^ ]", temp, path);
            printf("%s\n", temp);
        }
        else {
            temp_path = strstr(recvline, "www");
            sscanf(temp_path, "%[^\n]", temp, path);
        }

        if(strstr(temp, ":") != NULL) {
            sscanf(temp, "%[^:]:%d", host, &port);
        }
        else {
            strcpy(host, temp);
            port = 80;
            // port = 443;
        }

        if(path == NULL) {
            strcpy(path, "./");
        }

    }

    host[strlen(host) - 1] = 0;

    char http_request_out[100];
    strcat(http_request_out, method);
    strcat(http_request_out, " ");
    strcat(http_request_out, host);
    strcat(http_request_out, " ");


    for(int i = 0; i < forbidden_sites.size(); i++) {
        s_to_char = (char *)forbidden_sites.at(i).c_str();
        s_to_char[strlen(s_to_char) - 1] = 0;
        if(strcmp(host, s_to_char) == 0) {
            perror("Site on forbidden list.\n");
            exit(1);
        }
    }

    serverfd = find_server(host, port);

    strcat(http_request, recvline);

    write(serverfd, http_request, sizeof(http_request));
    if((n = read(serverfd, recvline, MAXLINE)) > 0)
    {
        recvline[n] = 0;
        if(fputs(recvline, stdout) == EOF)
        {
            perror("fputs error\n");
            exit(1);
        }
        temp_status = strstr(recvline, "HTTP/1.1 ");
        sscanf(temp_status, "%[^\n]", status);
        pthread_mutex_lock(&lock);
        acc_file.open(t_struct->a_file, std::ios_base::app);
        acc_file << time_buf << "127.0.0.1 " << http_request_out << status << " " << n << endl;
        pthread_mutex_unlock(&lock);

        write(t_struct->cfd, recvline, MAXLINE);
        bzero(recvline, MAXLINE);
    }

    close(serverfd);
    
    // SSL             *ssl;
    // X509            *certificate;
    // SSL_library_init();
    // SSL_load_error_strings();

    // const SSL_METHOD *meth = TLSv1_2_client_method();
    // if(method == NULL) {
    //     perror("SSL method failed to load.\n");
    //     exit(1);
    // }

    // SSL_CTX *ctx = SSL_CTX_new(method);
    // if(ctx == NULL) {
    //     perror("SSL context failed to load.\n");
    //     exit(1);
    // }

    // ssl = SSL_new(ctx);
    // SSL_set_fd(ssl, serverfd);
    // if(SSL_connect(ssl) == -1) {
    //    perror("SSL connection fail.\n");
    //    exit(1);
    // }

    // SSL_get_cipher(ssl);
    
    // SSL_write(clientfd, http_request, strlen(http_request));

    // if(int j = SSL_read(ssl, recvline, MAXLINE) > 0) {
    //     temp_status = strstr(recvline, "HTTP/1.1 ");
    //     sscanf(temp_status, "%[^\n]", status);
    //     pthread_mutex_lock(&lock);
    //     acc_file.open(t_struct->a_file, std::ios_base::app);
    //     acc_file << time_buf << "127.0.0.1 " << http_request_out << status << " " << n << endl;
    //     pthread_mutex_unlock(&lock);
    //     write(t_struct->cfd, recvline, MAXLINE);
    //     bzero(recvline, MAXLINE);
    // }

    // SSL_free(ssl);
    // close(serverfd);
    // SSL_CTX_free(ctx);    
    // SSL_shutdown();
    
    close(t_struct->cfd);
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    int                 sockfd, port_num;
    struct  sockaddr_in servaddr, cliaddr;
    socklen_t           len;
    pthread_t           tid;
    Thread_struct       t_struct;

    if(pthread_mutex_init(&lock, NULL) != 0) {
        perror("Mutex init has failed\n");
        exit(1);
    }

    if(argc != 4) {
        perror("Usage: bin/myproxy listen_port forbidden_sites_file_path access_log_file_path\n");
        exit(1);
    }

    if((port_num = atoi(argv[1])) < 1 || (port_num = atoi(argv[1])) > 65535) {
        perror("Invalid Port Number: Use ports 1 to 65535\n");
        exit(1);
    }

    t_struct.f_file = argv[2];
    t_struct.a_file = argv[3];


    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Sock error\n");
        exit(1);
    }

    const int reuse_time = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse_time, sizeof(int)) < 0) {
        perror("Reuse of sock failed\n");
        exit(1);
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port_num);

    if((bind(sockfd, (SA *)&servaddr, sizeof(servaddr))) < 0) {
        perror("Bind error\n");
        exit(1);
    }

    if(listen(sockfd, LISTENQ) < 0) {
        perror("Listen error\n");
        exit(1);
    }

    printf("Sock ready\n");

    for (; ;) {
        len = sizeof(cliaddr);
        t_struct.cfd = accept(sockfd, (SA *)&cliaddr, &len);

        pthread_create(&tid, NULL, proxy_thread, &t_struct);
    }

    close(sockfd);
    pthread_mutex_destroy(&lock);
    exit(0);
}


