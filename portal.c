/**
 * Dinstar Provison Application
 * Copyright (C) 2013-2015
 * All rights reserved
 *
 * @file    portal.c
 * @brief   portal process
 *
 *
 * @author  kyle
 * @version 1.0
 * @date    2015-04-08
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uci.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include "portal.h"

/* here lock is not necessary, do nothing */
#define portal_lock()
#define portal_unlock()

static struct portal_config_s g_portal_config;

/* show portal current config info */
static void portal_printf_config(struct portal_config_s *cfg)
{
    printf("portal config info:\r\n");
    printf("authtype:   %s\r\n", cfg->authtype);
    printf("timeout:    %d\r\n", cfg->timeout);
    printf("server:     %s\r\n", cfg->serverip);
    printf("serveri:    %x\r\n", cfg->serveri);
    printf("server port:%d\r\n", cfg->server_port);
    printf("local  port:%d\r\n", cfg->local_port);
    printf("username:   %s\r\n", cfg->username);
    printf("password:   %s\r\n", cfg->password);
    printf("ipauth:     %d\r\n", cfg->ipauth);
    printf("macauth:    %d\r\n", cfg->macauth);
    printf("multipath:  %d\r\n", cfg->multipath);

    return;
}

/* clean \0 \r \n character */
static void portal_buffer_format(char *buffer)
{
    char *p;

    p = buffer;
    while (*p != '\0')
    {
        if ((*p == '\r') || (*p == '\n'))
        {
            *p = '\0';
            break;
        }
        p++;
    }

    return;
}

/* Parse a string to see if it is valid decimal dotted quad IP V4  */
int portal_check_ip_valid(char *possibleip)
{
	unsigned int a1, a2, a3, a4;

	return (sscanf(possibleip, "%u.%u.%u.%u", &a1, &a2, &a3, &a4) == 4
			&& a1 < 256 && a2 < 256 && a3 < 256 && a4 < 256);
}

/* Parse a string to see if it is valid MAC address */
int portal_check_mac_valid(char *possiblemac)
{
	char hex2[3];
    
	return
		sscanf(possiblemac,
			   "%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]",
			   hex2, hex2, hex2, hex2, hex2, hex2) == 6;
}

int portal_execute(char *cmd_line)
{
	int status, retval;
	pid_t pid, rc;
	struct sigaction sa, oldsa;
	const char *new_argv[4];
	new_argv[0] = "/bin/sh";
	new_argv[1] = "-c";
	new_argv[2] = cmd_line;
	new_argv[3] = NULL;

	/* Temporarily get rid of SIGCHLD handler (see gateway.c), until child exits.
	 * Will handle SIGCHLD here with waitpid() in the parent. */
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
	if (sigaction(SIGCHLD, &sa, &oldsa) == -1) {
		syslog(LOG_ERR, "portal sigaction() failed to set default SIGCHLD handler: %s", strerror(errno));
	}

	pid = fork();
	if (pid == 0) 
    {
        /* execute the command  */
		execvp("/bin/sh", (char *const *)new_argv);
		exit(1);    
	} 
    else 
    {
		do {
            /* for the parent */
			rc = waitpid(pid, &status, 0);
			if (rc == -1) 
            {
				if (errno == ECHILD) 
                {
					retval = 0;
				} else {
					retval = -1;
				}
				break;
			}
			if (WIFEXITED(status)) 
            {
				retval = (WEXITSTATUS(status));
			}
			if (WIFSIGNALED(status)) 
            {
				retval = -1;
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));

		sigaction(SIGCHLD, &oldsa, NULL);

		return retval;
	}
}

void portal_system(char *cmd_line)
{   
    int i, rc;

    for (i = 0; i < 5; i++) 
    {
		rc = portal_execute(cmd_line);
		if (rc == 4) 
        {
			/* iptables error code 4 indicates a resource problem that might
			 * be temporary. So we retry to do a few times. (Mitar) */
			sleep(1);
		} else {
			break;
		}
	}

    return;
}

int portal_iptables(char *cmd_line)
{
    char echo_buffer[PORTAL_CMD_LEN];
    char echo_buffer2[PORTAL_CMD_LEN];
    char *opt;

    snprintf(echo_buffer2, sizeof(echo_buffer), "echo '%s' >> %s", cmd_line, PORTAL_FIREWALL_FILE);
    opt = strstr(echo_buffer2, "-I ");
    if (opt == NULL)
    {
        opt = strstr(echo_buffer2, "-A ");
    }
    if (opt != NULL)
    {
        *(opt+1) = 'D';
        
        portal_execute(echo_buffer2);
    }
    snprintf(echo_buffer, sizeof(echo_buffer), "echo '%s' >> %s", cmd_line, PORTAL_FIREWALL_FILE);
    portal_execute(cmd_line);
    portal_execute(echo_buffer);
}

/* show user list information */
static void portal_user_list_show(void)
{
    FILE *fp_user;
    char buffer[PORTAL_CMD_LEN];

    fp_user = fopen(PORTAL_USER_LOGIN_FILE, "r");
    if (NULL == fp_user)
    {
        return;
    }

    while (NULL != fgets(buffer, sizeof(buffer), fp_user))
    {
        printf("%s", buffer);
    }
    fclose(fp_user);

    return;
}

/* get local lan interface ip address */
static char portal_get_ipaddr(char *ip_buf, int len)
{
    #if 1
    FILE *fp;
    char buffer[PORTAL_NAME_LEN];

    fp = popen("uci get network.lan.ipaddr", "r" );
    if (fp == NULL)
    {
        return 0;
    }

    if (NULL != fgets(buffer, sizeof(buffer), fp))
    {
        portal_buffer_format(buffer);
        strncpy(ip_buf, buffer, len - 1);
    }
    
    pclose(fp);
    
    return 1;

    #else
   
    struct ifreq temp;
    struct sockaddr_in *myaddr;
    int fd = 0;
    int ret = -1;
    
    strcpy(temp.ifr_name, ifname);
    if((fd=socket(AF_INET, SOCK_STREAM, 0))<0)
    {
        return NULL;
    }
    ret = ioctl(fd, SIOCGIFADDR, &temp);
    close(fd);
    if(ret < 0)
        return NULL;
    
    myaddr = (struct sockaddr_in *)&(temp.ifr_addr);
    strcpy(ip_buf, inet_ntoa(myaddr->sin_addr));
    
    return ip_buf;
    #endif
}

/* get local lan interface ip address */
static char portal_add_local_ipaddr(void)
{
    char ipaddr[PORTAL_NAME_LEN];
    char buffer[PORTAL_CMD_LEN];
    int i;
    FILE *fp;

    portal_get_ipaddr(ipaddr, sizeof(ipaddr));
    snprintf(buffer, sizeof(buffer), "ipset add %s %s", PORTAL_USER_SYS_IPSET, ipaddr);
    portal_execute(buffer);

    for (i = 0; i <= 16; i++)
    {
        snprintf(buffer, sizeof(buffer), "uci get network.vlan%d.ipaddr", i);
        //printf("%s:%d cmd:%s\r\n", __FUNCTION__, __LINE__, buffer);
        fp = popen(buffer, "r" );
        if (fp != NULL)
        {
            if (NULL != fgets(ipaddr, sizeof(ipaddr), fp))
            {
                portal_buffer_format(ipaddr);
                snprintf(buffer, sizeof(buffer), "ipset add %s %s", PORTAL_USER_SYS_IPSET, ipaddr);
                portal_execute(buffer);
            }
            pclose(fp);
        }
    }
    
}

/* stop protal service */
static void portal_local_service_stop(void)
{
    char buffer[PORTAL_CMD_LEN];

    snprintf(buffer, sizeof(buffer), "iptables -t nat -D zone_lan_prerouting -p tcp"
            " -m multiport --dports 80,8080 -j %s 2>/dev/null", PORTAL_IPTABLE_CHAIN);
    portal_system(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -t nat -F %s 2>/dev/null", PORTAL_IPTABLE_CHAIN);
    portal_system(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -t nat -X %s 2>/dev/null", PORTAL_IPTABLE_CHAIN);
    portal_system(buffer);
    

    /* destory iptable forward rule */
    snprintf(buffer, sizeof(buffer), "iptables -D forwarding_rule -m set ! --match-set %s src -j %s 2>/dev/null", 
            PORTAL_USER_IPSET, PORTAL_IPTABLE_CHAIN);
    portal_system(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -F %s 2>/dev/null", PORTAL_IPTABLE_CHAIN);
    portal_system(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -X %s 2>/dev/null", PORTAL_IPTABLE_CHAIN);
    portal_system(buffer);
    
    /* init ipset info */
    snprintf(buffer, sizeof(buffer), "ipset flush %s 2>/dev/null", PORTAL_USER_IPSET);
    portal_system(buffer);
    snprintf(buffer, sizeof(buffer), "ipset flush %s 2>/dev/null", PORTAL_USER_SYS_IPSET);
    portal_system(buffer);
    snprintf(buffer, sizeof(buffer), "ipset flush %s 2>/dev/null", PORTAL_USER_W_IPSET);
    portal_system(buffer);
    snprintf(buffer, sizeof(buffer), "ipset flush %s 2>/dev/null", PORTAL_USER_WM_IPSET);
    portal_system(buffer);
    

    snprintf(buffer, sizeof(buffer), "echo  > %s", PORTAL_FIREWALL_FILE);
    portal_execute(buffer);
    snprintf(buffer, sizeof(buffer), "rm -f %s", PORTAL_USER_LOGIN_FILE);
    portal_execute(buffer);

    /* 删除定时执行任务"sed -i '/,%s,/d' %s" */
    portal_execute("sed -i '/portal check all/d' /etc/crontabs/root");
    portal_execute("/etc/init.d/cron restart");

    return;
}

/* start protal service */
static void portal_local_service_start(void)
{
    char buffer[PORTAL_CMD_LEN];
    //char ipaddr[PORTAL_NAME_LEN];
    
    portal_printf_config(&g_portal_config);

    portal_local_service_stop();
    
    /* init ipset info */
    snprintf(buffer, sizeof(buffer), "ipset -N %s hash:ip 2>/dev/null", PORTAL_USER_IPSET);
    portal_execute(buffer);
    snprintf(buffer, sizeof(buffer), "ipset -N %s hash:ip 2>/dev/null", PORTAL_USER_SYS_IPSET);
    portal_execute(buffer);
    snprintf(buffer, sizeof(buffer), "ipset -N %s hash:ip 2>/dev/null", PORTAL_USER_W_IPSET);
    portal_execute(buffer);
    snprintf(buffer, sizeof(buffer), "ipset -N %s hash:mac 2>/dev/null", PORTAL_USER_WM_IPSET);
    portal_execute(buffer);
    

    /* init iptables chain */
    snprintf(buffer, sizeof(buffer), "iptables -N %s 2>/dev/null", PORTAL_IPTABLE_CHAIN);
    portal_execute(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -N %s 2>/dev/null", PORTAL_IPTABLE_CHAIN);
    portal_iptables(buffer);

    snprintf(buffer, sizeof(buffer), "iptables -t nat -N %s 2>/dev/null", PORTAL_IPTABLE_CHAIN);
    portal_execute(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -t nat -N %s 2>/dev/null", PORTAL_IPTABLE_CHAIN);
    portal_iptables(buffer);

    snprintf(buffer, sizeof(buffer), "iptables -t nat -I zone_lan_prerouting -p tcp"
            " -m multiport --dports 80,8080 -j %s", PORTAL_IPTABLE_CHAIN);
    portal_iptables(buffer);

    snprintf(buffer, sizeof(buffer), "iptables -t nat -I %s -p tcp"
            " -m set ! --match-set %s src -j REDIRECT --to-ports %d", 
            PORTAL_IPTABLE_CHAIN, PORTAL_USER_IPSET, g_portal_config.local_port);
    portal_iptables(buffer);

    /* 保证正常访问本机 */
    //portal_get_ipaddr(ipaddr, sizeof(ipaddr));
    portal_add_local_ipaddr();
    
    snprintf(buffer, sizeof(buffer), "iptables -t nat -I %s -m set --match-set %s dst -j RETURN", 
                                     PORTAL_IPTABLE_CHAIN, PORTAL_USER_SYS_IPSET);
    portal_iptables(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -t nat -I %s -m set --match-set %s src -j RETURN", 
                                     PORTAL_IPTABLE_CHAIN, PORTAL_USER_W_IPSET);
    portal_iptables(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -t nat -I %s -m set --match-set %s src -j RETURN", 
                                     PORTAL_IPTABLE_CHAIN, PORTAL_USER_WM_IPSET);
    portal_iptables(buffer);

    /* create iptable forward rule */
    snprintf(buffer, sizeof(buffer), "iptables -A forwarding_rule -m set ! --match-set %s src -j %s", 
            PORTAL_USER_IPSET, PORTAL_IPTABLE_CHAIN);
    portal_iptables(buffer);
    
    /* add portal chain rule*/
    snprintf(buffer, sizeof(buffer), "iptables -I %s -m set --match-set %s src -j RETURN", 
                                     PORTAL_IPTABLE_CHAIN, PORTAL_USER_W_IPSET);
    portal_iptables(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -I %s -m set --match-set %s src -j RETURN", 
                                     PORTAL_IPTABLE_CHAIN, PORTAL_USER_WM_IPSET);
    portal_iptables(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -A %s -p tcp --dport 53 -j ACCEPT", PORTAL_IPTABLE_CHAIN);
    portal_iptables(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -A %s -p udp --dport 53 -j ACCEPT", PORTAL_IPTABLE_CHAIN);
    portal_iptables(buffer);
    snprintf(buffer, sizeof(buffer), "iptables -A %s -j reject", PORTAL_IPTABLE_CHAIN);
    portal_iptables(buffer);

    /* 添加定时执行任务 */
    snprintf(buffer, sizeof(buffer), "echo '*/%d * * * * portal check all' >> /etc/crontabs/root", g_portal_config.timeout);
    portal_execute(buffer);
    portal_execute("/etc/init.d/cron restart");

    return;
}

/* load portal system config info */
static int portal_load_config(struct portal_config_s *cfg)
{
    char *ptr;
    FILE *fp_cfg;
    char buffer[PORTAL_CMD_LEN];
    
    memset(cfg, 0, sizeof(struct portal_config_s));
    fp_cfg = fopen(PORTAL_SYS_CONFIG_FILE, "r");
    if (fp_cfg == NULL)
    {
        return -1;
    }

    /* 默认多用户登录模式 */
    cfg->multipath = 1;
    while (NULL != fgets(buffer, sizeof(buffer), fp_cfg))
    {
        ptr = buffer;
        while (*ptr != '\0')
        {
            if (*ptr == '\'' || *ptr == '\"' || *ptr == '\t' )
            {
                *ptr = ' ';
            }
            if (*ptr == '\r' || *ptr == '\n')
            {
                *ptr = '\0';
                break;
            }
            ptr++;
        }

        ptr = buffer;
        while (*ptr == ' ')
        {
            ptr++;
        }
        if (NULL != strstr(ptr, "option authtype "))
        {
            sscanf(ptr, "option authtype %s", cfg->authtype);
            continue;
        }

        if (NULL != strstr(ptr, "option timeout "))
        {
            sscanf(ptr, "option timeout %d", &cfg->timeout);
            continue;
        }

        if (NULL != strstr(ptr, "option server "))
        {
            sscanf(ptr, "option server %s", cfg->serverip);
            inet_aton(cfg->serverip, (struct in_addr *)&cfg->serveri);
            continue;
        }

        if (NULL != strstr(ptr, "option server_port "))
        {
            sscanf(ptr, "option server_port %d", &cfg->server_port);
            continue;
        }

        if (NULL != strstr(ptr, "option local_port "))
        {
            sscanf(ptr, "option local_port %d", &cfg->local_port);
            continue;
        }

        if (NULL != strstr(ptr, "option username "))
        {
            sscanf(ptr, "option username %s", cfg->username);
            continue;
        }

        if (NULL != strstr(ptr, "option password "))
        {
            sscanf(ptr, "option password %s", cfg->password);
            continue;
        }

        if (NULL != strstr(ptr, "option ipauth "))
        {
            sscanf(ptr, "option ipauth %d", &cfg->ipauth);
            continue;
        }

        if (NULL != strstr(ptr, "option macauth "))
        {
            sscanf(ptr, "option macauth %d", &cfg->macauth);
            continue;
        }

        if (NULL != strstr(ptr, "option multipath "))
        {
            sscanf(ptr, "option multipath %d", &cfg->multipath);
            continue;
        }
    }

    fclose(fp_cfg);
    
    return 0;
}

static int portal_user_addr_is_login(char *name, char *ipaddr)
{
    FILE *fp;
    char buffer[PORTAL_CMD_LEN];
    char *pipaddr;
    int  res = 0;

    if (name == NULL)
    {
        return res;
    }

    snprintf(buffer, sizeof(buffer), "cat %s |grep %s,", PORTAL_USER_LOGIN_FILE, name);
    fp = popen(buffer, "r" );
    if (fp == NULL)
    {
        return res;
    }

    while (NULL != fgets(buffer, sizeof(buffer), fp))
    {
        if ((0 == strncmp(buffer, name, strlen(name))) && buffer[strlen(name)] == ',')
        {
            pipaddr = strstr(buffer, ipaddr);
            if ((pipaddr != NULL) && (*(pipaddr - 1) == ',') && (*(pipaddr + strlen(ipaddr)) == ','))
            {
                res = 1;
                break;
            }
        }
    }
    
    pclose(fp);

    return res;
}

/* user info: kyle x.x.x.x aa:bb:cc:dd:ee:ee */
static void portal_online_user(char *name, char *password, char *ipaddr, char *mac)
{
    char cmdBuff[PORTAL_CMD_LEN];
    time_t    tnow;
    struct tm *timenow;

    if (ipaddr == NULL) //name's value is null ok.
        return;

    /* 认证用户上线 */
    snprintf(cmdBuff, sizeof(cmdBuff), "ipset add %s %s", PORTAL_USER_IPSET, ipaddr);
    system(cmdBuff);

    if (0 != portal_user_addr_is_login(name, ipaddr))
    {
        /* user aleardy login, don't make a new record */
        return;
    }

    time(&tnow);
    timenow = localtime(&tnow);
    if (name != NULL)
    {
        snprintf(cmdBuff, sizeof(cmdBuff), "echo '%s,%s,%s,%s,%d-%d-%d %.2d:%.2d:%.2d' >> %s", 
                name, password, ipaddr, mac, timenow->tm_year + 1900, timenow->tm_mon + 1, timenow->tm_mday, 
                timenow->tm_hour, timenow->tm_min, timenow->tm_sec, 
                PORTAL_USER_LOGIN_FILE);
    }
    else
    {
        snprintf(cmdBuff, sizeof(cmdBuff), "echo '%s,%s,%s,%s,%d-%d-%d %.2d:%.2d:%.2d' >> %s", 
                ipaddr, ipaddr, ipaddr, ipaddr, timenow->tm_year + 1900, timenow->tm_mon + 1, timenow->tm_mday, 
                timenow->tm_hour, timenow->tm_min, timenow->tm_sec, 
                PORTAL_USER_LOGIN_FILE);
    }
    system(cmdBuff);
    
    syslog(LOG_WARNING, "user(%s) portal authentication success, user online.", ipaddr);

    return;
}

/* user info: kyle x.x.x.x */
static void portal_offline_user(char *name, char *ipaddr)
{
    char cmdBuff[PORTAL_CMD_LEN];

    if (ipaddr == NULL)
        return;

    /* 认证用户下线 */
    snprintf(cmdBuff, sizeof(cmdBuff), "ipset del %s %s", PORTAL_USER_IPSET, ipaddr);
    system(cmdBuff);

    if (name != NULL)
    {
        snprintf(cmdBuff, sizeof(cmdBuff), "sed -i '/^%s,/d' %s", name, PORTAL_USER_LOGIN_FILE);
    }
    else
    {
        snprintf(cmdBuff, sizeof(cmdBuff), "sed -i '/,%s,/d' %s", ipaddr, PORTAL_USER_LOGIN_FILE);   
    }
    system(cmdBuff);
    syslog(LOG_WARNING, "user(%s) portal authentication timeout, user offline.", name != NULL ? name : ipaddr);

    return;
}

/* check user has alrady logged */
static int portal_user_is_login(char *name)
{
    FILE *fp;
    char buffer[PORTAL_CMD_LEN];
    int  res = 0;

    snprintf(buffer, sizeof(buffer), "cat %s |grep %s,", PORTAL_USER_LOGIN_FILE, name);
    fp = popen(buffer, "r" );
    if (fp == NULL)
    {
        return res;
    }

    while (NULL != fgets(buffer, sizeof(buffer), fp))
    {
        if ((0 == strncmp(buffer, name, strlen(name))) && buffer[strlen(name)] == ',')
        {
            //pclose(fp);
            //return 1;
            res++;
        }
    }
    
    pclose(fp);

    return res;
}

/* check user status for user information buffer */
static int _portal_check_user_status(char *buffer, char *ipaddr)
{
    if (NULL != strstr(buffer, ipaddr))
    {
        return 1;
    }

    return 0;
}

/* check user status */
static int portal_check_user_status(char *ipaddr)
{
    FILE *fp_arp = NULL;
    char *arpBuff = NULL;
    struct stat fileData;

    fp_arp = fopen(PORTAL_ARP_USER_FILE, "r");
    if (NULL == fp_arp)
    {
        goto error;
    }
    if (0 != stat(PORTAL_ARP_USER_FILE, &fileData))
    {
        goto error;
    }
    arpBuff = (char *)malloc(fileData.st_size + 1);
    if (NULL == arpBuff)
    {
        goto error;
    }
    memset(arpBuff, 0, fileData.st_size + 1);
    fread(arpBuff, fileData.st_size, 1, fp_arp);
    fclose(fp_arp);
    fp_arp = NULL;

    if (1 == _portal_check_user_status(arpBuff, ipaddr))
    {
        /* 认证用户当前在线 */
        printf("%s online\r\n", ipaddr);
    }
    else
    {
        portal_offline_user(NULL, ipaddr);
        printf("%s offline\r\n", ipaddr);
    }

    free(arpBuff);
    
    return 1;

error:
    if (NULL != arpBuff)
    {
        free(arpBuff);
    }
    if (NULL != fp_arp)
    {
        fclose(fp_arp);
    }
    
    return 0;
}

static int portal_check_all_user_config(void)
{
    FILE *fp_user = NULL;
    /**
    char username[PORTAL_NAME_LEN];
    char password[PORTAL_NAME_LEN];
    char mac[PORTAL_NAME_LEN];
    char ipaddr[PORTAL_NAME_LEN];
    char datetime[PORTAL_NAME_LEN];
    char time[PORTAL_NAME_LEN];
    **/
    char *username, *password, *mac, *ipaddr, *datetime;
    
    char userBuff[PORTAL_CMD_LEN];
    int res;

    fp_user = fopen(PORTAL_USER_LOGIN_FILE, "r");
    if (NULL == fp_user)
    {
        return 0;
    }

    while (NULL != fgets(userBuff, sizeof(userBuff), fp_user))
    {
        portal_buffer_format(userBuff);
        username = userBuff;
        password = strchr(userBuff, ',');
        if (NULL == password)
        {
            continue;
        }
        *password = '\0';
        password++;

        ipaddr = strchr(password, ',');
        if (NULL == ipaddr)
        {
            continue;
        }
        *ipaddr = '\0';
        ipaddr++;

        mac = strchr(ipaddr, ',');
        if (NULL == mac)
        {
            continue;
        }
        *mac = '\0';
        mac++;

        datetime = strchr(mac, ',');
        if (NULL == datetime)
        {
            continue;
        }
        *datetime = '\0';
        datetime++;

        //printf("%s:%d name:%s, pwd:%s, ip:%s, mac:%s, date:%s\r\n", 
        //        __FUNCTION__, __LINE__, username, password, ipaddr, mac, datetime);
        
        res = portal_auth_user(username, password, ipaddr, mac);
        if (0 == res)
        {
            portal_offline_user(username, ipaddr);
        }
    }
    fclose(fp_user);
    
    /* 删除定时执行任务 */
    portal_execute("sed -i '/portal check all/d' /etc/crontabs/root");
    /* 添加定时执行任务 */
    snprintf(userBuff, sizeof(userBuff), "echo '*/%d * * * * portal check all' >> /etc/crontabs/root", g_portal_config.timeout);
    portal_execute(userBuff);
    portal_execute("/etc/init.d/cron restart");
   
    return 1;
}


/* check all user status */
static int portal_check_all_user_status(void)
{
    int userbeginflag = 0;
    FILE *fp_user = NULL;
    FILE *fp_arp = NULL;
    char *arpBuff = NULL;
    char userBuff[PORTAL_CMD_LEN];
    //struct stat fileData;
    int  filesize = 80*1024;/* 80k= 1024条arp记录 */

    //fp_arp = fopen("/proc/net/arp", "r");
    fp_arp = popen("cat /proc/net/arp |grep -v eth1 |grep -v 0x0", "r" );
    if (NULL == fp_arp)
    {
        goto error;
    }
    /**
    if (0 != stat("/proc/net/arp", &fileData))
    {
        goto error;
    }
    fseek(fp_arp, 0L, SEEK_END);
    filesize = ftell(fp_arp);
    fseek(fp_arp, 0L, SEEK_SET);
    **/
    
    arpBuff = (char *)malloc(filesize);
    if (NULL == arpBuff)
    {
        goto error;
    }
    memset(arpBuff, 0, filesize);
    fread(arpBuff, filesize - 1, 1, fp_arp);
    pclose(fp_arp);
    fp_arp = NULL;

    snprintf(userBuff, sizeof(userBuff), "ipset list %s", PORTAL_USER_IPSET);
    fp_user = popen(userBuff, "r" );
    if (NULL == fp_user)
    {
        goto error;
    }

    userbeginflag = 0;
    while (NULL != fgets(userBuff, sizeof(userBuff), fp_user))
    {
        if (NULL != strstr(userBuff, "Members:"))
        {
            userbeginflag = 1;
            continue;
        }
        if (1 == userbeginflag)
        {
            portal_buffer_format(userBuff);
            if (NULL != strstr(arpBuff, userBuff))
            {
                /* 认证用户当前在线 */
                printf("find user:%s online...\r\n", userBuff);
            }
            else
            {
                portal_offline_user(NULL, userBuff);
            }
        }
    }

    free(arpBuff);
    pclose(fp_user);
   
    return 1;

error:
    if (NULL != arpBuff)
    {
        free(arpBuff);
    }
    if (NULL != fp_user)
    {
        pclose(fp_user);
    }
    if (NULL != fp_arp)
    {
        pclose(fp_arp);
    }
    
    return 0;
}

/* check user ip address */
static int portal_check_user_ipaddr(char *buffer, char *ipaddr)
{
    char *ptr, *ch;
    char *inner = NULL;
    unsigned int    src_ip;
    unsigned int    dst_ip;
    int             dst_imask;
    unsigned int    dst_mask;

    /* 如果ip地址为0.0.0.0或者0.0.0.0/0表示为全地址*/
    if ((0 == strcmp(buffer, "0.0.0.0")) || (0 == strcmp(buffer, "0.0.0.0/0")))
    {
        return 1;
    }

    /* IP字符串转化成点分十进制格式 */
    src_ip = inet_addr(ipaddr);

    ptr = strtok_r(buffer, ",", &inner);
	while (NULL != ptr)
	{
        if (0 == strcmp(ptr, ipaddr))
        {
            return 1;
        }
        
        if (NULL != (ch = strchr(ptr, '/')))
        {
            /* 判断是否属于一个网络地址 */
            *ch = '\0';
            dst_ip = inet_addr(ptr);
            *ch = '/';
            ch++;

            if (portal_check_ip_valid(ch))
            {
                dst_mask = inet_addr(ch);
                //printf("%s:%d 0x%X\r\n", __FUNCTION__, __LINE__, dst_mask);
            }
            else 
            {
                sscanf(ch, "%d", &dst_imask);
                //dst_mask = IP_GET_IPMASK_BY_BITS(dst_imask);
                //src_ip = htonl(src_ip);
                //dst_ip = htonl(dst_ip);            
                dst_mask = htonl(IP_GET_IPMASK_BY_BITS(dst_imask));
                //printf("%s:%d 0x%X\r\n", __FUNCTION__, __LINE__, dst_mask);
            }
            
            if (((unsigned int)src_ip & dst_mask) == ((unsigned int)dst_ip & dst_mask))
            {
                return 1;
            }
        }

		ptr = strtok_r(NULL, ",", &inner);
	}
    
    return 0;
}

/* check user mac address */
static int portal_check_user_mac(char *macBuff, char *mac)
{
    /* 如果地址为0.0.0.0.0.0表示为全地址*/
    if (0 == strcmp(macBuff, "00:00:00:00:00:00"))
    {
        return 1;
    }

    if (NULL != strstr(macBuff, mac))
    {
        return 1;
    }
	
	if (NULL != strcasestr(macBuff, mac))
    {
        return 1;
    }

    return 0;
}

/* portal local authentication mode */
static int portal_local_auth(char *username, char *passwd, char *ipaddr, char *mac)
{
    int userFind = 0;
    FILE *fp_user_cfg;
    char *buffer;
    int  userNameLen;
    char szUsername[PORTAL_NAME_LEN];
    char szPasswd[PORTAL_NAME_LEN];
    char szIpaddr[PORTAL_CMD_LEN];
    char szMac[PORTAL_CMD_LEN];
    int  multipath, flag;

    /* 非多PC登录情况下，用户已经登录，认证失败 */
    if (g_portal_config.multipath == 0)
    {
        if (0 != portal_user_is_login(username))
        {
            /* 多用户登录失败 */
            syslog(LOG_WARNING, "user(%s) has already logged, authentication fail.", username);
            return 0;
        }
    }
   
    fp_user_cfg = fopen(PORTAL_ACCOUNT_CONFIG, "r");
    if (NULL == fp_user_cfg)
    {
        syslog(LOG_WARNING, "open user account database:%s error.", PORTAL_ACCOUNT_CONFIG);
        return 0;
    }
 
    buffer = (char *)malloc(READ_LINE_LEN);
    if (buffer == NULL)
    {
        syslog(LOG_ERR, "portal malloc memory fail.");
        fclose(fp_user_cfg);
        return 0;
    }
  
    userNameLen = strlen(username);
    while (NULL != fgets(buffer, READ_LINE_LEN, fp_user_cfg))
    {
        if (buffer[0] == '#')
        {
            continue;
        }
  
        if ((0 == strncmp(buffer, username, userNameLen)) 
            && (buffer[userNameLen] == ' '))
        {
            userFind = 1;
            break;
        }
    }
    /* free open file first */
    fclose(fp_user_cfg);
    if (0 == userFind)
    {
        syslog(LOG_WARNING, "user's(%s) name invalid, portal authentication fail.", username);
        free(buffer);
        return 0;
    }

    memset(szIpaddr, 0, sizeof(szIpaddr));
    memset(szMac, 0, sizeof(szMac));
    /* get user config info */
    sscanf(buffer, "%s %s %d %d %s %s", szUsername, szPasswd, &multipath, &flag, szIpaddr, szMac);
    if (0 != strcmp(szUsername, username) || 0 != strcmp(szPasswd, passwd))
    {
        free(buffer);
        syslog(LOG_WARNING, "user's(%s) password invalid, portal authentication fail.", username);
        return 0;
    }
    //printf("%s:%d multi:%d, flag:%d\r\n", __FUNCTION__, __LINE__, multipath, flag);

    if (g_portal_config.ipauth == 1)
    {
        if (1 != portal_check_user_ipaddr(szIpaddr, ipaddr))
        {
            free(buffer);
            syslog(LOG_WARNING, "user's(%s) ip address invalid, portal authentication fail.", username);
            return 0;
        }
    }

    if (g_portal_config.macauth == 1)
    {   
        if (1 != portal_check_user_mac(szMac, mac))
        {
            free(buffer);
            syslog(LOG_WARNING, "user's(%s) mac address invalid, portal authentication fail.", username);
            return 0;
        }
    }

    return 1;
}

/* portal authentication user information */
int portal_auth_user(char *username, char *passwd, char *ipaddr, char *mac)
{
    if (username == NULL || passwd == NULL || ipaddr == NULL || mac == NULL)
    {   
        syslog(LOG_WARNING, "portal authentication, missing necessary parameters.\r\n");
        return 0;
    }

    /* check ip addr invalid */
    if (!portal_check_ip_valid(ipaddr))
    {
        syslog(LOG_WARNING, "portal authentication, input invalid ip address parameters.\r\n");
        return 0;
    }

    /* check mac addr invalid */
    if ((strlen(mac) != 17) || !portal_check_mac_valid(mac))
    {
        syslog(LOG_WARNING, "portal authentication, input invalid mac address parameters.\r\n");
        return 0;
    }
    
    if (0 == strcmp("local", g_portal_config.authtype))
    {
        return portal_local_auth(username, passwd, ipaddr, mac);
    }
    else if (0 == strcmp("radius", g_portal_config.authtype))
    {
        /* Radius认证暂不支持 */
        return 0;
    }

    return 0;
}

/**
 * portal main function
 */
int main(int argc, char *argv[])
{
    char *username;
    char *passwd;
    char *ipaddr;
    char *mac;

	if ((argc < 2) || 0 == strcmp("help", argv[1]))
	{
        goto error;
	}
    
    portal_load_config(&g_portal_config);

    if (argc == 2)
    {
        if (0 == strcmp("start", argv[1]))
        {
            if (0 == strcmp("local", g_portal_config.authtype))
            {
                portal_local_service_start();
            }

            return 1;
        }

        if (0 == strcmp("stop", argv[1]))
        {
            if (0 == strcmp("local", g_portal_config.authtype))
            {
                portal_local_service_stop();
            }

            return 1;
        }

        if (0 == strcmp("list", argv[1]))
        {
            if (0 == strcmp("local", g_portal_config.authtype))
            {
                portal_user_list_show();
            }

            return 1;
        }

        goto error;
    }

    username = passwd = ipaddr = mac = NULL;
    if (0 == strcmp("online", argv[1]))
    {
        ipaddr = argv[2];
        portal_online_user(NULL, NULL, ipaddr, NULL);
        
        return 1;
    }

    if (0 == strcmp("offline", argv[1]))
    {
        ipaddr = argv[2];
        if (portal_check_ip_valid(ipaddr))
        {
            portal_offline_user(NULL, ipaddr);
        }
        else
        {
            portal_offline_user(ipaddr, NULL);
        }
         
        return 1;
    }

    if (0 == strcmp("auth", argv[1]))
    {
        if (argc < 4)
        {
            goto error;
            return 0;
        }
        switch(argc)
        {
            case 6:
                mac = argv[5];
            case 5:
                ipaddr = argv[4];
            case 4:
                username = argv[2];
                passwd = argv[3];
                break;
            default:
                break;
        }

        /* 认证方式为local */
        if (1 == portal_auth_user(username, passwd, ipaddr, mac))
        {
            /* 认证成功 */
            portal_online_user(username, passwd, ipaddr, mac);
            
            printf("result:1\r\n");
            return 1;
        }
        else
        {
            printf("result:0\r\n");
            return 0;
        }
        
    }

    if (0 == strcmp("check", argv[1]))
    {
        if (0 == strcmp("all", argv[2]))
        {
            portal_check_all_user_status();
        }
        else if (0 == strcmp("update", argv[2]))
        {
            portal_check_all_user_config();
        }
        else
        {
            ipaddr = argv[2];
            
            portal_check_user_status(ipaddr);
        }

        return 1;
    }

error:
	
    printf("Configuration:\n"
		"  online x.x.x.x \n"
		"  offline x.x.x.x \n"
		"  auth username password ipaddr mac\n"
		"  list\n"
		"  check {all | x.x.x.x [mac] | update} \n");

    return 0;    
}

#ifdef __cplusplus
}
#endif

