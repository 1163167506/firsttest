/**
 * Dinstar Provison Application
 * Copyright (C) 2013-2015
 * All rights reserved
 *
 * @file    portal.h
 * @brief   
 *
 *
 * @author  kyle
 * @version 1.0
 * @date    2013-12-14
*/

#ifndef __PORTAL_H__
#define __PORTAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#define PORTAL_NAME_LEN         32
#define PORTAL_CMD_LEN          512
#define READ_LINE_LEN           1024

#define PORTAL_USER_IPSET       "authList"
#define PORTAL_USER_SYS_IPSET   "authSysList"
#define PORTAL_USER_W_IPSET     "authWList"
#define PORTAL_USER_WM_IPSET    "authWMList"
#define PORTAL_USER_LOGIN_FILE  "/tmp/portal_login.list"
#define PORTAL_LOGIN_LOG_FILE   "/tmp/portal_login.log"
#define PORTAL_SYS_CONFIG_FILE  "/etc/config/portal"
#define PORTAL_ACCOUNT_CONFIG   "/etc/portal_account.txt"
//#define PORTAL_IPSET_USER_FILE  "/var/run/useripset.list"
#define PORTAL_ARP_USER_FILE    "/proc/net/arp"
#define PORTAL_IPTABLE_CHAIN    "portal_rules"
#define PORTAL_FIREWALL_FILE    "/etc/firewall.portal"

#define IP_GET_IPMASK_BY_BITS(bits)     ((~0)<<(32-bits))

struct portal_config_s {
    unsigned char   running;
	char            authtype[PORTAL_NAME_LEN];
    unsigned int    timeout;
    unsigned int    local_port;
    unsigned int    serveri;
    char            serverip[PORTAL_NAME_LEN];
    unsigned int    server_port;
    char            username[PORTAL_NAME_LEN];
	char            password[PORTAL_NAME_LEN];
    unsigned int    ipauth;
    unsigned int    macauth;
    unsigned int    multipath;
};

#ifdef __cplusplus
}
#endif

#endif

