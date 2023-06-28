//#include <jni.h>
//#include <string>
//#include "stdio.h"

//JNIEXPORT jstring JNICALL
//Java_com_example_jni222_MainActivity_stringFromJNI(
//        JNIEnv *env, jclass clazz) {
//    char str[] = "Hello from C ";
//    return (*env)->NewStringUTF(env, str);
//}
// Our code implementation is based on the framework provided by John Schember
/* Copyright (C) 2017 by John Schember <john@nachtimwald.com>


#include <netdb.h>
#if defined(ANDROID) || defined(__ANDROID__)
#include <time.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <jni.h>

#include <android/log.h>

#include <unistd.h>


#include "ares_setup.h"
#include "ares.h"
#include "ares_android.h"
#include "ares_private.h"

#include <assert.h>



#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif

#include "ares_nameser.h"

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_getopt.h"
#include "ares_nowarn.h"

#ifndef HAVE_STRDUP
#  include "ares_strdup.h"
#  define strdup(ptr) ares_strdup(ptr)
#endif

#ifndef HAVE_STRCASECMP
#  include "ares_strcasecmp.h"
#  define strcasecmp(p1,p2) ares_strcasecmp(p1,p2)
#endif

#ifndef HAVE_STRNCASECMP
#  include "ares_strcasecmp.h"
#  define strncasecmp(p1,p2,n) ares_strncasecmp(p1,p2,n)
#endif

#ifdef WATT32
#undef WIN32  /* Redefined in MingW headers */
#endif

#include <pthread.h>


ares_channel channel;

struct nv {
    const char *name;
    int value;
};

static const struct nv flags[] = {
        { "usevc",            ARES_FLAG_USEVC },
        { "primary",          ARES_FLAG_PRIMARY },
        { "igntc",            ARES_FLAG_IGNTC },
        { "norecurse",        ARES_FLAG_NORECURSE },
        { "stayopen",         ARES_FLAG_STAYOPEN },
        { "noaliases",        ARES_FLAG_NOALIASES }
};
static const int nflags = sizeof(flags) / sizeof(flags[0]);

static const struct nv classes[] = {
        { "IN",       C_IN },
        { "CHAOS",    C_CHAOS },
        { "HS",       C_HS },
        { "ANY",      C_ANY },
        { "QoS Query",      C_QOS_Query },
        { "QoS Response",      C_QOS_Response }
};
static const int nclasses = sizeof(classes) / sizeof(classes[0]);

static const struct nv types[] = {
        { "A",        T_A },
        { "NS",       T_NS },
        { "MD",       T_MD },
        { "MF",       T_MF },
        { "CNAME",    T_CNAME },
        { "SOA",      T_SOA },
        { "MB",       T_MB },
        { "MG",       T_MG },
        { "MR",       T_MR },
        { "NULL",     T_NULL },
        { "WKS",      T_WKS },
        { "PTR",      T_PTR },
        { "HINFO",    T_HINFO },
        { "MINFO",    T_MINFO },
        { "MX",       T_MX },
        { "TXT",      T_TXT },
        { "RP",       T_RP },
        { "AFSDB",    T_AFSDB },
        { "X25",      T_X25 },
        { "ISDN",     T_ISDN },
        { "RT",       T_RT },
        { "NSAP",     T_NSAP },
        { "NSAP_PTR", T_NSAP_PTR },
        { "SIG",      T_SIG },
        { "KEY",      T_KEY },
        { "PX",       T_PX },
        { "GPOS",     T_GPOS },
        { "AAAA",     T_AAAA },
        { "LOC",      T_LOC },
        { "SRV",      T_SRV },
        { "AXFR",     T_AXFR },
        { "MAILB",    T_MAILB },
        { "MAILA",    T_MAILA },
        { "NAPTR",    T_NAPTR },
        { "DS",       T_DS },
        { "SSHFP",    T_SSHFP },
        { "RRSIG",    T_RRSIG },
        { "NSEC",     T_NSEC },
        { "DNSKEY",   T_DNSKEY },
        { "CAA",      T_CAA },
        { "URI",      T_URI },
        { "ANY",      T_ANY },
        { "QoS",      T_QOS }
//  { "QOS_Response",      C_QOS_Response }
};
static const int ntypes = sizeof(types) / sizeof(types[0]);

static const char *opcodes[] = {
        "QUERY", "IQUERY", "STATUS", "(reserved)", "NOTIFY",
        "(unknown)", "(unknown)", "(unknown)", "(unknown)",
        "UPDATEA", "UPDATED", "UPDATEDA", "UPDATEM", "UPDATEMA",
        "ZONEINIT", "ZONEREF"
};

static const char *rcodes[] = {
        "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
        "(unknown)", "(unknown)", "(unknown)", "(unknown)", "(unknown)",
        "(unknown)", "(unknown)", "(unknown)", "(unknown)", "NOCHANGE"
};

static void callback(void *arg, int status, int timeouts,
                     unsigned char *abuf, int alen);
static const unsigned char *display_question(const unsigned char *aptr,
                                             const unsigned char *abuf,
                                             int alen);
static const unsigned char *display_rr(const unsigned char *aptr,
                                       const unsigned char *abuf, int alen, int cnt, int flag_qos);
static int convert_query (char **name, int use_bitstring);
static const char *type_name(int type);
static const char *class_name(int dnsclass);
static void usage(void);
static void destroy_addr_list(struct ares_addr_node *head);
static void append_addr_list(struct ares_addr_node **head,
                             struct ares_addr_node *node);
static void print_help_info_adig(void);


static JavaVM *android_jvm = NULL;
static jobject android_connectivity_manager = NULL;

/* ConnectivityManager.getActiveNetwork */
static jmethodID android_cm_active_net_mid = NULL;
/* ConnectivityManager.getLinkProperties */
static jmethodID android_cm_link_props_mid = NULL;
/* LinkProperties.getDnsServers */
static jmethodID android_lp_dns_servers_mid = NULL;
/* LinkProperties.getDomains */
static jmethodID android_lp_domains_mid = NULL;
/* List.size */
static jmethodID android_list_size_mid = NULL;
/* List.get */
static jmethodID android_list_get_mid = NULL;
/* InetAddress.getHostAddress */
static jmethodID android_ia_host_addr_mid = NULL;


//static JNINativeMethod funcs[] = {
//        { "initialize_native",     "(Landroid/net/ConnectivityManager;)I",
//                (void *)&ares_library_init_android}
//};

#define JNIREG_CLASS "com/example/jni222/MainActivity"


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    jclass  cls = NULL;
    jint    res;

    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
        return -1;

//  cls = (*env)->FindClass(env, JNIT_CLASS);
    cls = (*env)->FindClass(env, JNIREG_CLASS);
    if (cls == NULL)
        return -1;

//  res = (*env)->RegisterNatives(env, cls, funcs, sizeof(funcs)/sizeof(funcs[0]));
//  if (res != 0)
//    return -1;

    ares_library_init_jvm(vm);
    return JNI_VERSION_1_6;
}


static jclass jni_get_class(JNIEnv *env, const char *path)
{
    jclass cls = NULL;

    if (env == NULL || path == NULL || *path == '\0')
        return NULL;

    cls = (*env)->FindClass(env, path);
    if ((*env)->ExceptionOccurred(env)) {
        (*env)->ExceptionClear(env);
        return NULL;
    }
    return cls;
}

static jmethodID jni_get_method_id(JNIEnv *env, jclass cls,
                                   const char *func_name, const char *signature)
{
    jmethodID mid = NULL;

    if (env == NULL || cls == NULL || func_name == NULL || *func_name == '\0' ||
        signature == NULL || *signature == '\0')
    {
        return NULL;
    }

    mid = (*env)->GetMethodID(env, cls, func_name, signature);
    if ((*env)->ExceptionOccurred(env))
    {
        (*env)->ExceptionClear(env);
        return NULL;
    }

    return mid;
}

void ares_library_init_jvm(JavaVM *jvm)
{
    android_jvm = jvm;
}

int ares_library_init_android(jobject connectivity_manager)
{
    JNIEnv *env = NULL;
    int need_detatch = 0;
    int res;
    int ret = ARES_ENOTINITIALIZED;
    jclass obj_cls = NULL;

    if (android_jvm == NULL)
        goto cleanup;

    res = (*android_jvm)->GetEnv(android_jvm, (void **)&env, JNI_VERSION_1_6);
    if (res == JNI_EDETACHED)
    {
        env = NULL;
        res = (*android_jvm)->AttachCurrentThread(android_jvm, &env, NULL);
        need_detatch = 1;
    }
    if (res != JNI_OK || env == NULL)
        goto cleanup;

    android_connectivity_manager =
            (*env)->NewGlobalRef(env, connectivity_manager);
    if (android_connectivity_manager == NULL)
        goto cleanup;

    /* Initialization has succeeded. Now attempt to cache the methods that will be
     * called by ares_get_android_server_list. */
    ret = ARES_SUCCESS;

    /* ConnectivityManager in API 1. */
    obj_cls = jni_get_class(env, "android/net/ConnectivityManager");
    if (obj_cls == NULL)
        goto cleanup;

    /* ConnectivityManager.getActiveNetwork in API 23. */
    android_cm_active_net_mid =
            jni_get_method_id(env, obj_cls, "getActiveNetwork",
                              "()Landroid/net/Network;");
    if (android_cm_active_net_mid == NULL)
        goto cleanup;

    /* ConnectivityManager.getLinkProperties in API 21. */
    android_cm_link_props_mid =
            jni_get_method_id(env, obj_cls, "getLinkProperties",
                              "(Landroid/net/Network;)Landroid/net/LinkProperties;");
    if (android_cm_link_props_mid == NULL)
        goto cleanup;

    /* LinkProperties in API 21. */
    (*env)->DeleteLocalRef(env, obj_cls);
    obj_cls = jni_get_class(env, "android/net/LinkProperties");
    if (obj_cls == NULL)
        goto cleanup;

    /* getDnsServers in API 21. */
    android_lp_dns_servers_mid = jni_get_method_id(env, obj_cls, "getDnsServers",
                                                   "()Ljava/util/List;");
    if (android_lp_dns_servers_mid == NULL)
        goto cleanup;

    /* getDomains in API 21. */
    android_lp_domains_mid = jni_get_method_id(env, obj_cls, "getDomains",
                                               "()Ljava/lang/String;");
    if (android_lp_domains_mid == NULL)
        goto cleanup;

    (*env)->DeleteLocalRef(env, obj_cls);
    obj_cls = jni_get_class(env, "java/util/List");
    if (obj_cls == NULL)
        goto cleanup;

    android_list_size_mid = jni_get_method_id(env, obj_cls, "size", "()I");
    if (android_list_size_mid == NULL)
        goto cleanup;

    android_list_get_mid = jni_get_method_id(env, obj_cls, "get",
                                             "(I)Ljava/lang/Object;");
    if (android_list_get_mid == NULL)
        goto cleanup;

    (*env)->DeleteLocalRef(env, obj_cls);
    obj_cls = jni_get_class(env, "java/net/InetAddress");
    if (obj_cls == NULL)
        goto cleanup;

    android_ia_host_addr_mid = jni_get_method_id(env, obj_cls, "getHostAddress",
                                                 "()Ljava/lang/String;");
    if (android_ia_host_addr_mid == NULL)
        goto cleanup;

    (*env)->DeleteLocalRef(env, obj_cls);
    goto done;

    cleanup:
    if (obj_cls != NULL)
        (*env)->DeleteLocalRef(env, obj_cls);

    android_cm_active_net_mid = NULL;
    android_cm_link_props_mid = NULL;
    android_lp_dns_servers_mid = NULL;
    android_lp_domains_mid = NULL;
    android_list_size_mid = NULL;
    android_list_get_mid = NULL;
    android_ia_host_addr_mid = NULL;

    done:
    if (need_detatch)
        (*android_jvm)->DetachCurrentThread(android_jvm);

    return ret;
}

int ares_library_android_initialized(void)
{
    if (android_jvm == NULL || android_connectivity_manager == NULL)
        return ARES_ENOTINITIALIZED;
    return ARES_SUCCESS;
}

void ares_library_cleanup_android(void)
{
    JNIEnv *env = NULL;
    int need_detatch = 0;
    int res;

    if (android_jvm == NULL || android_connectivity_manager == NULL)
        return;

    res = (*android_jvm)->GetEnv(android_jvm, (void **)&env, JNI_VERSION_1_6);
    if (res == JNI_EDETACHED)
    {
        env = NULL;
        res = (*android_jvm)->AttachCurrentThread(android_jvm, &env, NULL);
        need_detatch = 1;
    }
    if (res != JNI_OK || env == NULL)
        return;

    android_cm_active_net_mid = NULL;
    android_cm_link_props_mid = NULL;
    android_lp_dns_servers_mid = NULL;
    android_lp_domains_mid = NULL;
    android_list_size_mid = NULL;
    android_list_get_mid = NULL;
    android_ia_host_addr_mid = NULL;

    (*env)->DeleteGlobalRef(env, android_connectivity_manager);
    android_connectivity_manager = NULL;

    if (need_detatch)
        (*android_jvm)->DetachCurrentThread(android_jvm);
}

char **ares_get_android_server_list(size_t max_servers,
                                    size_t *num_servers)
{
    JNIEnv *env = NULL;
    jobject active_network = NULL;
    jobject link_properties = NULL;
    jobject server_list = NULL;
    jobject server = NULL;
    jstring str = NULL;
    jint nserv;
    const char *ch_server_address;
    int res;
    size_t i;
    char **dns_list = NULL;
    int need_detatch = 0;

    if (android_jvm == NULL || android_connectivity_manager == NULL ||
        max_servers == 0 || num_servers == NULL)
    {
        return NULL;
    }

    if (android_cm_active_net_mid == NULL || android_cm_link_props_mid == NULL ||
        android_lp_dns_servers_mid == NULL || android_list_size_mid == NULL ||
        android_list_get_mid == NULL || android_ia_host_addr_mid == NULL)
    {
        return NULL;
    }

    res = (*android_jvm)->GetEnv(android_jvm, (void **)&env, JNI_VERSION_1_6);
    if (res == JNI_EDETACHED)
    {
        env = NULL;
        res = (*android_jvm)->AttachCurrentThread(android_jvm, &env, NULL);
        need_detatch = 1;
    }
    if (res != JNI_OK || env == NULL)
        goto done;

    /* JNI below is equivalent to this Java code.
       import android.content.Context;
       import android.net.ConnectivityManager;
       import android.net.LinkProperties;
       import android.net.Network;
       import java.net.InetAddress;
       import java.util.List;

       ConnectivityManager cm = (ConnectivityManager)this.getApplicationContext()
         .getSystemService(Context.CONNECTIVITY_SERVICE);
       Network an = cm.getActiveNetwork();
       LinkProperties lp = cm.getLinkProperties(an);
       List<InetAddress> dns = lp.getDnsServers();
       for (InetAddress ia: dns) {
         String ha = ia.getHostAddress();
       }

       Note: The JNI ConnectivityManager object and all method IDs were previously
             initialized in ares_library_init_android.
     */

    active_network = (*env)->CallObjectMethod(env, android_connectivity_manager,
                                              android_cm_active_net_mid);
    if (active_network == NULL)
        goto done;

    link_properties =
            (*env)->CallObjectMethod(env, android_connectivity_manager,
                                     android_cm_link_props_mid, active_network);
    if (link_properties == NULL)
        goto done;

    server_list = (*env)->CallObjectMethod(env, link_properties,
                                           android_lp_dns_servers_mid);
    if (server_list == NULL)
        goto done;

    nserv = (*env)->CallIntMethod(env, server_list, android_list_size_mid);
    if (nserv > (jint)max_servers)
        nserv = (jint)max_servers;
    if (nserv <= 0)
        goto done;
    *num_servers = (size_t)nserv;

    dns_list = ares_malloc(sizeof(*dns_list)*(*num_servers));
    for (i=0; i<*num_servers; i++)
    {
        server = (*env)->CallObjectMethod(env, server_list, android_list_get_mid,
                                          (jint)i);
        dns_list[i] = ares_malloc(64);
        dns_list[i][0] = 0;
        if (server == NULL)
        {
            continue;
        }
        str = (*env)->CallObjectMethod(env, server, android_ia_host_addr_mid);
        ch_server_address = (*env)->GetStringUTFChars(env, str, 0);
        strncpy(dns_list[i], ch_server_address, 64);
        (*env)->ReleaseStringUTFChars(env, str, ch_server_address);
        (*env)->DeleteLocalRef(env, str);
        (*env)->DeleteLocalRef(env, server);
    }

    done:
    if ((*env)->ExceptionOccurred(env))
        (*env)->ExceptionClear(env);

    if (server_list != NULL)
        (*env)->DeleteLocalRef(env, server_list);
    if (link_properties != NULL)
        (*env)->DeleteLocalRef(env, link_properties);
    if (active_network != NULL)
        (*env)->DeleteLocalRef(env, active_network);

    if (need_detatch)
        (*android_jvm)->DetachCurrentThread(android_jvm);
    return dns_list;
}

char *ares_get_android_search_domains_list(void)
{
    JNIEnv *env = NULL;
    jobject active_network = NULL;
    jobject link_properties = NULL;
    jstring domains = NULL;
    const char *domain;
    int res;
    char *domain_list = NULL;
    int need_detatch = 0;

    if (android_jvm == NULL || android_connectivity_manager == NULL)
    {
        return NULL;
    }

    if (android_cm_active_net_mid == NULL || android_cm_link_props_mid == NULL ||
        android_lp_domains_mid == NULL)
    {
        return NULL;
    }

    res = (*android_jvm)->GetEnv(android_jvm, (void **)&env, JNI_VERSION_1_6);
    if (res == JNI_EDETACHED)
    {
        env = NULL;
        res = (*android_jvm)->AttachCurrentThread(android_jvm, &env, NULL);
        need_detatch = 1;
    }
    if (res != JNI_OK || env == NULL)
        goto done;

    /* JNI below is equivalent to this Java code.
       import android.content.Context;
       import android.net.ConnectivityManager;
       import android.net.LinkProperties;

       ConnectivityManager cm = (ConnectivityManager)this.getApplicationContext()
         .getSystemService(Context.CONNECTIVITY_SERVICE);
       Network an = cm.getActiveNetwork();
       LinkProperties lp = cm.getLinkProperties(an);
       String domains = lp.getDomains();
       for (String domain: domains.split(",")) {
         String d = domain;
       }

       Note: The JNI ConnectivityManager object and all method IDs were previously
             initialized in ares_library_init_android.
     */

    active_network = (*env)->CallObjectMethod(env, android_connectivity_manager,
                                              android_cm_active_net_mid);
    if (active_network == NULL)
        goto done;

    link_properties =
            (*env)->CallObjectMethod(env, android_connectivity_manager,
                                     android_cm_link_props_mid, active_network);
    if (link_properties == NULL)
        goto done;

    /* Get the domains. It is a common separated list of domains to search. */
    domains = (*env)->CallObjectMethod(env, link_properties,
                                       android_lp_domains_mid);
    if (domains == NULL)
        goto done;

    /* Split on , */
    domain = (*env)->GetStringUTFChars(env, domains, 0);
    domain_list = ares_strdup(domain);
    (*env)->ReleaseStringUTFChars(env, domains, domain);
    (*env)->DeleteLocalRef(env, domains);

    done:
    if ((*env)->ExceptionOccurred(env))
        (*env)->ExceptionClear(env);

    if (link_properties != NULL)
        (*env)->DeleteLocalRef(env, link_properties);
    if (active_network != NULL)
        (*env)->DeleteLocalRef(env, active_network);

    if (need_detatch)
        (*android_jvm)->DetachCurrentThread(android_jvm);
    return domain_list;
}


JNIEXPORT jint JNICALL
Java_com_example_jni222_MainActivity_initialize_1native(JNIEnv *env, jclass clazz,
                                                        jobject connectivity_manager) {
    // TODO: implement initialize_native()

//  env = NULL;
    int need_detatch = 0;
    int res;
    int ret = ARES_ENOTINITIALIZED;
    jclass obj_cls = NULL;

    if (android_jvm == NULL)
        goto cleanup;

    res = (*android_jvm)->GetEnv(android_jvm, (void **)&env, JNI_VERSION_1_6);
    if (res == JNI_EDETACHED)
    {
        env = NULL;
        res = (*android_jvm)->AttachCurrentThread(android_jvm, &env, NULL);
        need_detatch = 1;
    }
    if (res != JNI_OK || env == NULL)
        goto cleanup;

    android_connectivity_manager =
            (*env)->NewGlobalRef(env, connectivity_manager);
    if (android_connectivity_manager == NULL)
        goto cleanup;

    /* Initialization has succeeded. Now attempt to cache the methods that will be
     * called by ares_get_android_server_list. */
    ret = ARES_SUCCESS;

    /* ConnectivityManager in API 1. */
    obj_cls = jni_get_class(env, "android/net/ConnectivityManager");
    if (obj_cls == NULL)
        goto cleanup;

    /* ConnectivityManager.getActiveNetwork in API 23. */
    android_cm_active_net_mid =
            jni_get_method_id(env, obj_cls, "getActiveNetwork",
                              "()Landroid/net/Network;");
    if (android_cm_active_net_mid == NULL)
        goto cleanup;

    /* ConnectivityManager.getLinkProperties in API 21. */
    android_cm_link_props_mid =
            jni_get_method_id(env, obj_cls, "getLinkProperties",
                              "(Landroid/net/Network;)Landroid/net/LinkProperties;");
    if (android_cm_link_props_mid == NULL)
        goto cleanup;

    /* LinkProperties in API 21. */
    (*env)->DeleteLocalRef(env, obj_cls);
    obj_cls = jni_get_class(env, "android/net/LinkProperties");
    if (obj_cls == NULL)
        goto cleanup;

    /* getDnsServers in API 21. */
    android_lp_dns_servers_mid = jni_get_method_id(env, obj_cls, "getDnsServers",
                                                   "()Ljava/util/List;");
    if (android_lp_dns_servers_mid == NULL)
        goto cleanup;

    /* getDomains in API 21. */
    android_lp_domains_mid = jni_get_method_id(env, obj_cls, "getDomains",
                                               "()Ljava/lang/String;");
    if (android_lp_domains_mid == NULL)
        goto cleanup;

    (*env)->DeleteLocalRef(env, obj_cls);
    obj_cls = jni_get_class(env, "java/util/List");
    if (obj_cls == NULL)
        goto cleanup;

    android_list_size_mid = jni_get_method_id(env, obj_cls, "size", "()I");
    if (android_list_size_mid == NULL)
        goto cleanup;

    android_list_get_mid = jni_get_method_id(env, obj_cls, "get",
                                             "(I)Ljava/lang/Object;");
    if (android_list_get_mid == NULL)
        goto cleanup;

    (*env)->DeleteLocalRef(env, obj_cls);
    obj_cls = jni_get_class(env, "java/net/InetAddress");
    if (obj_cls == NULL)
        goto cleanup;

    android_ia_host_addr_mid = jni_get_method_id(env, obj_cls, "getHostAddress",
                                                 "()Ljava/lang/String;");
    if (android_ia_host_addr_mid == NULL)
        goto cleanup;

    (*env)->DeleteLocalRef(env, obj_cls);
    goto done;

    cleanup:
    if (obj_cls != NULL)
        (*env)->DeleteLocalRef(env, obj_cls);

    android_cm_active_net_mid = NULL;
    android_cm_link_props_mid = NULL;
    android_lp_dns_servers_mid = NULL;
    android_lp_domains_mid = NULL;
    android_list_size_mid = NULL;
    android_list_get_mid = NULL;
    android_ia_host_addr_mid = NULL;

    done:
    if (need_detatch)
        (*android_jvm)->DetachCurrentThread(android_jvm);


    return ret;

}

//void dns_callback (void* arg, int status, int timeouts, struct hostent* host)
//{
//  if(status == ARES_SUCCESS)
//    printf("host->h_name: \n", host->h_name);
//  else
////    std::cout << "lookup failed: " << status << '\n';
//    printf("lookup failed: %d\n", status);
//}

//void main_loop(ares_channel& channel)
//{
//    int nfds, count;
//    fd_set readers, writers;
//    timeval tv, *tvp;
//    while (1) {
//      FD_ZERO(&readers);
//      FD_ZERO(&writers);
//      nfds = ares_fds(channel, &readers, &writers);
//      if (nfds == 0)
//      break;
//      tvp = ares_timeout(channel, NULL, &tv);
//      count = select(nfds, &readers, &writers, NULL, tvp);
//      ares_process(channel,
//      &readers, &writers);
//    }
//}



static int CloudServerHostIsIP(const char * serverhost) {
    struct in_addr addr;
    int lsuccess;
    lsuccess = inet_pton(AF_INET, serverhost, &addr);
    return lsuccess > 0 ? 0 : -1;

}

static void DNSCallBack(void* arg, int status, int timeouts, struct hostent* host)
{
    char **lpSrc;
    char  * lpHost = (char *)arg;

    if (status == ARES_SUCCESS)
    {
        for (lpSrc = host->h_addr_list; *lpSrc; lpSrc++)
        {
            char addr_buf[32] = "";
            ares_inet_ntop(host->h_addrtype, *lpSrc, addr_buf, sizeof(addr_buf));
            if (strlen(addr_buf) != 0)
            {
                strcpy(lpHost, addr_buf);
                break;
            }
        }
    }
}

#define IP_LEN 32

typedef struct {
    char host[64];
    char ip[10][IP_LEN];
    int count;
}IpList;


IpList *ips = NULL;

void dns_callback (void* arg, int status, int timeouts, struct hostent* hptr) 
{
//  IpList *ips = (IpList*)arg;
    ips = (IpList*)arg;
    if( ips == NULL ){
        assert (0 == 1);

    }
    if(status == ARES_SUCCESS){
        strncpy(ips->host, hptr->h_name, sizeof(ips->host));
        char **pptr=hptr->h_addr_list;
        for(int i=0; *pptr!=NULL && i<10; pptr++,++i){
            inet_ntop(hptr->h_addrtype, *pptr, ips->ip[ips->count++], IP_LEN);
        }
    }else{
//    std::cout << "lookup failed: " << status << std::endl;

        printf("lookup failed: \n");

        assert (0 == 1);
    }



}



JNIEXPORT jstring JNICALL
Java_com_example_jni222_MainActivity_getipbyhostname(JNIEnv *env, jclass clazz,
                                                     jstring hostname) {
    // TODO: implement getipbyhostname()

    const char *nativeString_hostname = (*env)->GetStringUTFChars(env, hostname, 0);

    int res = 0;

    ares_channel channel;

    if((res = ares_init(&channel)) != ARES_SUCCESS) {

//    return 1;
        return "error";
    }

//  struct in_addr ip;

//  inet_aton(argv[1], &ip);

    IpList ips;

    memset(&ips, 0, sizeof(ips));


    ares_gethostbyname(channel, nativeString_hostname, AF_INET, dns_callback, (void*)(&ips));



    int nfds;
    fd_set readers, writers;
    struct timeval tv, *tvp;
    while (true)
    {
        FD_ZERO(&readers);
        FD_ZERO(&writers);
        nfds = ares_fds(channel, &readers, &writers);  
        if (nfds == 0) break;
        tvp = ares_timeout(channel, NULL, &tv);
        select(nfds, &readers, &writers, NULL, tvp);  
        ares_process(channel, &readers, &writers);  
    }


    int len = strlen(ips.ip[0]);



    (*env)->ReleaseStringUTFChars(env, hostname, nativeString_hostname);

    ares_destroy(channel);
    ares_library_cleanup();

    char digest[] = "test";

    jstring temp = (*env)->NewStringUTF(env, (const char*)ips.ip[0]);


//  return res;
//  return "test";
    return temp;
}

//struct dns_ret_obj{
//
//};

char Ips[100] = {0};

struct dns_ret_obj{
    char name[50];
    char Ips[50];
    char QoS[50];
    char Hash_url[33];
};

struct dns_ret_obj dns_qos_obj[10];



int cnt_q = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


JNIEXPORT jstring JNICALL
Java_com_example_jni222_MainActivity_dnsQueryQoS(JNIEnv *env, jclass clazz, jstring hostnames)
{

    char error[] = "error";

    jstring err_str = (*env)->NewStringUTF(env, error);

    const char *hostnames_c_str = (*env)->GetStringUTFChars(env, hostnames, 0);

    ares_channel channel;
    int c, i, optmask = ARES_OPT_FLAGS, dnsclass = C_IN, type = T_A;
    int status, nfds, count;
    int use_ptr_helper = 0;
    struct ares_options options;
    struct hostent *hostent;
    fd_set read_fds, write_fds;
    struct timeval *tvp, tv;
    struct ares_addr_node *srvr, *servers = NULL;

#ifdef USE_WINSOCK
    WORD wVersionRequested = MAKEWORD(USE_WINSOCK,USE_WINSOCK);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#endif

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS)
    {
        fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
        return err_str;
    }

//    options.udp_port = 1077;
    options.udp_port = 53;
    optmask |= ARES_OPT_UDP_PORT;

    options.flags = ARES_FLAG_EDNS;
    options.servers = NULL;
    options.nservers = 0;

    status = ares_init_options(&channel, &options, optmask);

    if (status != ARES_SUCCESS)
    {
        fprintf(stderr, "ares_init_options: %s\n",
                ares_strerror(status));
        return err_str;
    }

    if(servers)
    {
        status = ares_set_servers(channel, servers);
        destroy_addr_list(servers);
        if (status != ARES_SUCCESS)
        {
            fprintf(stderr, "ares_init_options: %s\n",
                    ares_strerror(status));
            return err_str;
        }
    }

    /* Initiate the queries, one per command-line argument.  If there is
     * only one query to do, supply NULL as the callback argument;
     * otherwise, supply the query name as an argument so we can
     * distinguish responses for the user when printing them out.
     */
//  for (i = 1; *argv; i++, argv++)

//    char hostname[] = "www.google.com";



    __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "hostnames_c_str is %s\n", hostnames_c_str);
    char *token, *str, *tofree;
    tofree = str = strdup(hostnames_c_str); // we own hostnames_c_str's memory now
    int k = 1;
    while ((token = strsep(&str, ";"))){
        __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "token is %s\n", token);

        char *query = token;

        __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "query is %s\n", query);


        if (type == T_PTR && dnsclass == C_IN && use_ptr_helper)
            if (!convert_query (&query, use_ptr_helper >= 2))
                continue;

//      ares_query(channel, query, dnsclass, type, callback, k++ < 3-1 ? (void*)query : NULL);
//        ares_query(channel, query, dnsclass, type, callback, (void*)query);



    }


//    struct dns_ret_obj dns_qos_objects[100];

//    int k = 0;

    /* Wait for all queries to complete. */
    for (;;)
    {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if (nfds == 0)
            break;
        tvp = ares_timeout(channel, NULL, &tv);
        count = select(nfds, &read_fds, &write_fds, NULL, tvp);  // select: non-blocking
        if (count < 0 && (status = SOCKERRNO) != EINVAL)
        {
            printf("select fail: %d", status);
            return err_str;
        }
        ares_process(channel, &read_fds, &write_fds);

//        dns_qos_objects[k++] = dns_qos_obj;



    }
    // dns_return data format : ip11-ip12-ip1n$c,l,r | ip21-ip22-ip2n$c,l,r
    char dns_return_data[100] = {0};

    dns_return_data[0] = '\0';

    __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "cnt_q: %d", cnt_q);

    for (int j = 0; j < cnt_q; j++){
//        __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "name: %s, Ips: %s", dns_qos_objects[j].name, dns_qos_objects[j].Ips);
        __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "name: %s, Ips: %s, QoS: %s", dns_qos_obj[j].name, dns_qos_obj[j].Ips, dns_qos_obj[j].QoS);
        strncat(dns_return_data, dns_qos_obj[j].Ips, strlen(dns_return_data) - 1);


//        strncpy(dns_return_data, dns_qos_objects[j].Ips, strlen(dns_return_data));
        dns_return_data[strlen(dns_return_data)] = '|';
    }

    dns_return_data[strlen(dns_return_data)-1] = '\0'; // remove the final '|' at the end of string

    __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "dns_return_data: %s", dns_return_data);

    jstring dns_return_data_java = (*env)->NewStringUTF(env, (const char*)dns_return_data);

    ares_destroy(channel);

    ares_library_cleanup();

#ifdef USE_WINSOCK
    WSACleanup();
#endif

    return dns_return_data_java;
}

static void callback(void *arg, int status, int timeouts,
                     unsigned char *abuf, int alen)
{



    cnt_q++;

    char *name = (char *) arg;
    int id, qr, opcode, aa, tc, rd, ra, rcode;
    unsigned int qdcount, ancount, nscount, arcount, i;
    const unsigned char *aptr;

    (void) timeouts;


    /* Display an error message if there was an error, but only stop if
     * we actually didn't get an answer buffer.
     */
    if (status != ARES_SUCCESS)
    {
//        printf("%s\n", ares_strerror(status));
        if (!abuf)
            return;
    }

    /* Won't happen, but check anyway, for safety. */
    if (alen < HFIXEDSZ)
        return;

    // int id, qr, opcode, aa, tc, rd, ra, rcode;
    /* Parse the answer header. */
    id = DNS_HEADER_QID(abuf);
    qr = DNS_HEADER_QR(abuf);
    opcode = DNS_HEADER_OPCODE(abuf);
    aa = DNS_HEADER_AA(abuf);
    tc = DNS_HEADER_TC(abuf);
    rd = DNS_HEADER_RD(abuf);
    ra = DNS_HEADER_RA(abuf);
    rcode = DNS_HEADER_RCODE(abuf);

//    abuf += sizeof(int ) * 8;

    //unsigned int qdcount, ancount, nscount, arcount, i;

    qdcount = DNS_HEADER_QDCOUNT(abuf);
    ancount = DNS_HEADER_ANCOUNT(abuf);
    nscount = DNS_HEADER_NSCOUNT(abuf);

//    abuf += sizeof (unsigned int ) * 3;

    arcount = DNS_HEADER_ARCOUNT(abuf);


    /* Display the questions. */
//    printf("Questions:\n");
    aptr = abuf + HFIXEDSZ;
    for (i = 0; i < qdcount; i++)
    {
        aptr = display_question(aptr, abuf, alen);
        if (aptr == NULL)
            return;
    }

    /* Display the answers. */
//    printf("Answers:\n");
    for (i = 0; i < ancount; i++)
    {
        aptr = display_rr(aptr, abuf, alen, cnt_q-1, 0);
        if (aptr == NULL)
            return;
    }

    /* Display the NS records. */
//    printf("NS records:\n");
    for (i = 0; i < nscount; i++)
    {
        aptr = display_rr(aptr, abuf, alen, cnt_q-1, 0);
        if (aptr == NULL)
            return;
    }

    /* Display the additional records. */
//    printf("Additional records:\n");
//    __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "arcount : %d\n", arcount);





    for (i = 0; i < arcount; i++)
    {
        if (arcount > 2)
            break;
//        __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "here is Additional records");
        pthread_mutex_lock(&mutex);
        aptr = display_rr(aptr, abuf, alen, cnt_q-1, i);
        pthread_mutex_unlock(&mutex);
        if (aptr == NULL)
//            return;
            break;
    }


}

static const unsigned char *display_question(const unsigned char *aptr,
                                             const unsigned char *abuf,
                                             int alen)
{
    char *name;
    int type, dnsclass, status;
    long len;

    /* Parse the question name. */
    status = ares_expand_name(aptr, abuf, alen, &name, &len);
    if (status != ARES_SUCCESS)
        return NULL;
    aptr += len;

    /* Make sure there's enough data after the name for the fixed part
     * of the question.
     */
    if (aptr + QFIXEDSZ > abuf + alen)
    {
        ares_free_string(name);
        return NULL;
    }

    /* Parse the question type and class. */
    type = DNS_QUESTION_TYPE(aptr);
    dnsclass = DNS_QUESTION_CLASS(aptr);

//    aptr += sizeof (int) * 2;

    aptr += QFIXEDSZ;

    /* Display the question, in a format sort of similar to how we will
     * display RRs.
     */
//    printf("\t%-15s.\t", name);

    strcpy(dns_qos_obj[cnt_q-1].name, name);
//    __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "question name: %s", name);

//    if (dnsclass != C_IN)
//        printf("\t%s", class_name(dnsclass));
//    printf("\t%s\n", type_name(type));
    ares_free_string(name);
    return aptr;
}

static const unsigned char *display_rr(const unsigned char *aptr,
                                       const unsigned char *abuf, int alen, int cnt, int flag_qos)
{
    const unsigned char *p;
    int type, dnsclass, ttl, dlen, status, i;
    long len;
    int vlen;
    char addr[46];
    union {
        unsigned char * as_uchar;
        char * as_char;
    } name;

    if (flag_qos){
        len = 1;
    } else{
        /* Parse the RR name. */
        status = ares_expand_name(aptr, abuf, alen, &name.as_char, &len);
        if (status != ARES_SUCCESS)
            return NULL;
    }

    aptr += len;

    /* Make sure there is enough data after the RR name for the fixed
     * part of the RR.
     */
    if (aptr + RRFIXEDSZ > abuf + alen)
    {
        ares_free_string(name.as_char);
        return NULL;
    }

    /* Parse the fixed part of the RR, and advance to the RR data
     * field. */
    type = DNS_RR_TYPE(aptr);

//    printf("type: %d\n", type);

    dnsclass = DNS_RR_CLASS(aptr);

//    printf("dnsclass: %d\n", dnsclass);

    ttl = DNS_RR_TTL(aptr);

//    printf("ttl: %d\n", ttl);

    dlen = DNS_RR_LEN(aptr);

//    printf("dlen: %d\n", dlen);

    aptr += RRFIXEDSZ;
    if (aptr + dlen > abuf + alen)
    {
        ares_free_string(name.as_char);
        return NULL;
    }

    /* Display the RR name, class, and type. */
//    printf("\t%-15s.\t%d", name.as_char, ttl);
//    if (dnsclass != C_IN)
//        printf("\t%s", class_name(dnsclass));
//    printf("\t%s", type_name(type));
    if (flag_qos == 0)
        ares_free_string(name.as_char);


//  printf("\n***********************************before switch*********************\n");

    /* Display the RR data.  Don't touch aptr. */
    switch (type)
    {
        case T_QOS:
            /* The RR data is qos info */



//      printf("T_QoS**************************\n");

//            printf("\t%s\n", aptr);
//            __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "Additional QoS dlen: %d", dlen);
            if (dlen > 32){
                char hash_url[33] = {0};
                memcpy(hash_url, aptr, 32);
                aptr += 32;
                long int loc = DNS__32BIT(aptr);
                long int lambda_para = DNS__32BIT(aptr+4);
//            long int reliability = DNS__32BIT(aptr+8);


//            __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "Additional QoS (loc, lambda_para): %s, %ld, %ld", hash_url, loc, lambda_para);


//            dns_qos_obj[cnt]
                // c, l, r
                char buf[100] = {0};
                char* buf_ = buf;

                sprintf(buf_, "%ld", loc);
                *(buf_ + strlen(buf_)) = ',';

                sprintf(buf_ + strlen(buf_), "%ld", lambda_para);
//            *(buf_ + strlen(buf_)) = ',';

//            memcpy(buf_+ strlen(buf_), hash_url, 33);
                strcpy(dns_qos_obj[cnt].Hash_url, hash_url);
                strcpy(dns_qos_obj[cnt].QoS, buf_);
            } else if (dlen == 32){ // only hash url exists, no qos data attached
                memcpy(dns_qos_obj[cnt].Hash_url, aptr, 32);
            } else {
                assert("dlen exception T_QOS\n");
            }



            break;



        case T_A:
            /* The RR data is a four-byte Internet address. */
            if (dlen != 4)
                return NULL;
//            printf("\t%s", ares_inet_ntop(AF_INET,aptr,addr,sizeof(addr)));

            const char* ip_ret = ares_inet_ntop(AF_INET,aptr,addr,sizeof(addr));
//            __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "ip_ret: %s", ip_ret);

//            strncpy(Ips, ip_ret, strlen(Ips));

            strcpy(dns_qos_obj[cnt].Ips, ip_ret);

//            __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "dns_qos_obj.Ips: %s", dns_qos_obj[cnt].Ips);

            break;

        case T_AAAA:
            /* The RR data is a 16-byte IPv6 address. */
            if (dlen != 16)
                return NULL;
//            printf("\t%s", ares_inet_ntop(AF_INET6,aptr,addr,sizeof(addr)));
            break;



        default:
            printf("\t[Unknown RR; cannot parse]");
            break;
    }
    printf("\n");

    return aptr + dlen;
}

/*
 * With the '-x' (or '-xx') and '-t PTR' options, convert a query for an
 * address into a more useful 'T_PTR' type question.
 * Like with an input 'query':
 *  "a.b.c.d"  ->  "d.c.b.a".in-addr.arpa"          for an IPv4 address.
 *  "a.b.c....x.y.z" -> "z.y.x....c.d.e.IP6.ARPA"   for an IPv6 address.
 *
 * An example from 'dig -x PTR 2001:470:1:1b9::31':
 *
 * QUESTION SECTION:
 * 1.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.9.b.1.0.1.0.0.0.0.7.4.0.1.0.0.2.IP6.ARPA. IN PTR
 *
 * ANSWER SECTION:
 * 1.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.9.b.1.0.1.0.0.0.0.7.4.0.1.0.0.2.IP6.ARPA. 254148 IN PTR ipv6.cybernode.com.
 *
 * If 'use_bitstring == 1', try to use the more compact RFC-2673 bitstring format.
 * Thus the above 'dig' query should become:
 *   [x13000000000000009b10100007401002].IP6.ARPA. IN PTR
 */
static int convert_query (char **name_p, int use_bitstring)
{
#ifndef MAX_IP6_RR
#define MAX_IP6_RR  (16*sizeof(".x.x") + sizeof(".IP6.ARPA") + 1)
#endif

#ifdef HAVE_INET_PTON
    #define ACCEPTED_RETVAL4 1
#define ACCEPTED_RETVAL6 1
#else
#define ACCEPTED_RETVAL4 32
#define ACCEPTED_RETVAL6 128
#endif

    static char new_name [MAX_IP6_RR];
    static const char hex_chars[] = "0123456789ABCDEF";

    union {
        struct in_addr       addr4;
        struct ares_in6_addr addr6;
    } addr;

    if (ares_inet_pton (AF_INET, *name_p, &addr.addr4) == 1)
    {
        unsigned long laddr = ntohl(addr.addr4.s_addr);
        unsigned long a1 = (laddr >> 24UL) & 0xFFUL;
        unsigned long a2 = (laddr >> 16UL) & 0xFFUL;
        unsigned long a3 = (laddr >>  8UL) & 0xFFUL;
        unsigned long a4 = laddr & 0xFFUL;

        snprintf(new_name, sizeof(new_name), "%lu.%lu.%lu.%lu.in-addr.arpa", a4, a3, a2, a1);
        *name_p = new_name;
        return (1);
    }

    if (ares_inet_pton(AF_INET6, *name_p, &addr.addr6) == 1)
    {
        char *c = new_name;
        const unsigned char *ip = (const unsigned char*) &addr.addr6;
        int   max_i = (int)sizeof(addr.addr6) - 1;
        int   i, hi, lo;

        /* Use the more compact RFC-2673 notation?
         * Currently doesn't work or unsupported by the DNS-servers I've tested against.
         */
        if (use_bitstring)
        {
            *c++ = '\\';
            *c++ = '[';
            *c++ = 'x';
            for (i = max_i; i >= 0; i--)
            {
                hi = ip[i] >> 4;
                lo = ip[i] & 15;
                *c++ = hex_chars [lo];
                *c++ = hex_chars [hi];
            }
            strcpy (c, "].IP6.ARPA");
        }
        else
        {
            for (i = max_i; i >= 0; i--)
            {
                hi = ip[i] >> 4;
                lo = ip[i] & 15;
                *c++ = hex_chars [lo];
                *c++ = '.';
                *c++ = hex_chars [hi];
                *c++ = '.';
            }
            strcpy (c, "IP6.ARPA");
        }
        *name_p = new_name;
        return (1);
    }
    printf("Address %s was not legal for this query.\n", *name_p);
    return (0);
}

static const char *type_name(int type)
{
    int i;

    for (i = 0; i < ntypes; i++)
    {
        if (types[i].value == type)
            return types[i].name;
    }
    return "(unknown)";
}

static const char *class_name(int dnsclass)
{
    int i;

    for (i = 0; i < nclasses; i++)
    {
        if (classes[i].value == dnsclass)
            return classes[i].name;
    }
    return "(unknown)";
}

static void usage(void)
{
    fprintf(stderr, "usage: adig [-h] [-d] [-f flag] [-s server] [-c class] "
                    "[-t type] [-T|U port] [-x|-xx] name ...\n");
    exit(1);
}

static void destroy_addr_list(struct ares_addr_node *head)
{
    while(head)
    {
        struct ares_addr_node *detached = head;
        head = head->next;
        free(detached);
    }
}

static void append_addr_list(struct ares_addr_node **head,
                             struct ares_addr_node *node)
{
    struct ares_addr_node *last;
    node->next = NULL;
    if(*head)
    {
        last = *head;
        while(last->next)
            last = last->next;
        last->next = node;
    }
    else
        *head = node;
}


/* Information from the man page. Formatting taken from man -h */
static void print_help_info_adig(void) {
    printf("adig, version %s \n\n", ARES_VERSION_STR);
    printf("usage: adig [-h] [-d] [-f flag] [-s server] [-c class] [-t type] [-T|U port] [-x | -xx] name ...\n\n"
           "  d : Print some extra debugging output.\n"
           "  f : Add a flag. Possible values for flag are igntc, noaliases, norecurse, primary, stayopen, usevc.\n"
           "  h : Display this help and exit.\n\n"
           "  T port   : Use specified TCP port to connect to DNS server.\n"
           "  U port   : Use specified UDP port to connect to DNS server.\n"
           "  c class  : Set the query class. Possible values for class are NY, CHAOS, HS, IN  (default).\n"
           "  s server : Connect to specified DNS server, instead of the system's default one(s).\n"
           "  t type   : Query records of specified type.  \n"
           "              Possible values for type are A  \n"
           "              (default), AAAA, AFSDB,  ANY,\n"
           "              AXFR, CNAME, GPOS, HINFO, ISDN,\n"
           "              KEY, LOC, MAILA, MAILB, MB, MD,\n"
           "              MF, MG, MINFO, MR, MX, NAPTR, NS,\n"
           "              NSAP, NSAP_PTR, NULL, PTR, PX, RP,\n"
           "              RT,  SIG,  SOA, SRV, TXT, URI, WKS, X25\n\n"
           " -x  : For a '-t PTR a.b.c.d' lookup, query for 'd.c.b.a.in-addr.arpa.'\n"
           " -xx : As above, but for IPv6, compact the format into a bitstring like\n"
           "       '[xabcdef00000000000000000000000000].IP6.ARPA.'\n");
    exit(0);
}


JNIEXPORT jint JNICALL
Java_com_example_jni222_PolymorphicWebService_initialize_1native(JNIEnv *env, jclass clazz,
                                                       jobject connectivity_manager) {
    // TODO: implement initialize_native()

    //  env = NULL;
    int need_detatch = 0;
    int res;
    int ret = ARES_ENOTINITIALIZED;
    jclass obj_cls = NULL;

    if (android_jvm == NULL)
        goto cleanup;

    res = (*android_jvm)->GetEnv(android_jvm, (void **)&env, JNI_VERSION_1_6);
    if (res == JNI_EDETACHED)
    {
        env = NULL;
        res = (*android_jvm)->AttachCurrentThread(android_jvm, &env, NULL);
        need_detatch = 1;
    }
    if (res != JNI_OK || env == NULL)
        goto cleanup;

    android_connectivity_manager =
            (*env)->NewGlobalRef(env, connectivity_manager);
    if (android_connectivity_manager == NULL)
        goto cleanup;

    /* Initialization has succeeded. Now attempt to cache the methods that will be
     * called by ares_get_android_server_list. */
    ret = ARES_SUCCESS;

    /* ConnectivityManager in API 1. */
    obj_cls = jni_get_class(env, "android/net/ConnectivityManager");
    if (obj_cls == NULL)
        goto cleanup;

    /* ConnectivityManager.getActiveNetwork in API 23. */
    android_cm_active_net_mid =
            jni_get_method_id(env, obj_cls, "getActiveNetwork",
                              "()Landroid/net/Network;");
    if (android_cm_active_net_mid == NULL)
        goto cleanup;

    /* ConnectivityManager.getLinkProperties in API 21. */
    android_cm_link_props_mid =
            jni_get_method_id(env, obj_cls, "getLinkProperties",
                              "(Landroid/net/Network;)Landroid/net/LinkProperties;");
    if (android_cm_link_props_mid == NULL)
        goto cleanup;

    /* LinkProperties in API 21. */
    (*env)->DeleteLocalRef(env, obj_cls);
    obj_cls = jni_get_class(env, "android/net/LinkProperties");
    if (obj_cls == NULL)
        goto cleanup;

    /* getDnsServers in API 21. */
    android_lp_dns_servers_mid = jni_get_method_id(env, obj_cls, "getDnsServers",
                                                   "()Ljava/util/List;");
    if (android_lp_dns_servers_mid == NULL)
        goto cleanup;

    /* getDomains in API 21. */
    android_lp_domains_mid = jni_get_method_id(env, obj_cls, "getDomains",
                                               "()Ljava/lang/String;");
    if (android_lp_domains_mid == NULL)
        goto cleanup;

    (*env)->DeleteLocalRef(env, obj_cls);
    obj_cls = jni_get_class(env, "java/util/List");
    if (obj_cls == NULL)
        goto cleanup;

    android_list_size_mid = jni_get_method_id(env, obj_cls, "size", "()I");
    if (android_list_size_mid == NULL)
        goto cleanup;

    android_list_get_mid = jni_get_method_id(env, obj_cls, "get",
                                             "(I)Ljava/lang/Object;");
    if (android_list_get_mid == NULL)
        goto cleanup;

    (*env)->DeleteLocalRef(env, obj_cls);
    obj_cls = jni_get_class(env, "java/net/InetAddress");
    if (obj_cls == NULL)
        goto cleanup;

    android_ia_host_addr_mid = jni_get_method_id(env, obj_cls, "getHostAddress",
                                                 "()Ljava/lang/String;");
    if (android_ia_host_addr_mid == NULL)
        goto cleanup;

    (*env)->DeleteLocalRef(env, obj_cls);


    int optmask = ARES_OPT_FLAGS;
    int status;
    struct ares_options options;


#ifdef USE_WINSOCK
    WORD wVersionRequested = MAKEWORD(USE_WINSOCK,USE_WINSOCK);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#endif

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS)
    {
        fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
//        return err_str;
    }

//    options.udp_port = 1077;  // change port number to 53, which could be used to test if the c-ares can work well (get ip address) when the dns server does not support qod query
    options.udp_port = 53;  // change port number to 53, which could be used to test if the c-ares can work well (get ip address) when the dns server does not support qod query
    optmask |= ARES_OPT_UDP_PORT;

    options.flags = ARES_FLAG_EDNS;
    options.servers = NULL;
    options.nservers = 0;

    status = ares_init_options(&channel, &options, optmask);

    if (status != ARES_SUCCESS)
    {
        fprintf(stderr, "ares_init_options: %s\n",
                ares_strerror(status));
//        return err_str;
    }


    goto done;

    cleanup:
    if (obj_cls != NULL)
        (*env)->DeleteLocalRef(env, obj_cls);

    android_cm_active_net_mid = NULL;
    android_cm_link_props_mid = NULL;
    android_lp_dns_servers_mid = NULL;
    android_lp_domains_mid = NULL;
    android_list_size_mid = NULL;
    android_list_get_mid = NULL;
    android_ia_host_addr_mid = NULL;









    done:
    if (need_detatch)
        (*android_jvm)->DetachCurrentThread(android_jvm);


    return ret;
}

JNIEXPORT jstring JNICALL
Java_com_example_jni222_PolymorphicWebService_getipbyhostname(JNIEnv *env, jclass clazz, jstring hostname) {
    // TODO: implement getipbyhostname()
    clock_t start = clock();
    const char *nativeString_hostname = (*env)->GetStringUTFChars(env, hostname, 0);
    struct ares_options options;
    int res = 0;
    int optmask = ARES_OPT_FLAGS;

    ares_channel channel;

    if((res = ares_init(&channel)) != ARES_SUCCESS) {

//    return 1;
        return "error";
    }

//  struct in_addr ip;

//  inet_aton(argv[1], &ip);

    options.udp_port = 53;
    optmask |= ARES_OPT_UDP_PORT;


    ares_init_options(&channel, &options, optmask);


    IpList ips;

    memset(&ips, 0, sizeof(ips));

    ares_gethostbyname(channel, nativeString_hostname, AF_INET, dns_callback, (void*)(&ips));



    int nfds;
    fd_set readers, writers;
    struct timeval tv, *tvp;
    while (true)
    {
        FD_ZERO(&readers);
        FD_ZERO(&writers);
        nfds = ares_fds(channel, &readers, &writers);  
        if (nfds == 0) break;
        tvp = ares_timeout(channel, NULL, &tv);
        select(nfds, &readers, &writers, NULL, tvp);  
        ares_process(channel, &readers, &writers); 
    }


    int len = strlen(ips.ip[0]);



    (*env)->ReleaseStringUTFChars(env, hostname, nativeString_hostname);

    ares_destroy(channel);
    ares_library_cleanup();

    char digest[] = "test";

    clock_t stop = clock();
    double elapsed = (double)(stop - start) * 1000.0 / CLOCKS_PER_SEC;
    __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "Post-Process Time elapsed in ms: %f", elapsed);

    char c_tmp[50] = {0}; //size of the number
    sprintf(c_tmp, "%g", elapsed);

//    jstring temp = (*env)->NewStringUTF(env, (const char*)ips.ip[0]);
    jstring temp = (*env)->NewStringUTF(env, (const char*)c_tmp);




//  return res;
//  return "test";
    return temp;
}


//-------------------------
// URL INFO
//-------------------------
struct xx_url_t {
    char	str[200];	/* URL strings */
};

/*------------------------------------------------------------------------------*/
/*
 * @brief   get hostname from URL 
 * @param	[i/o]	buf		work-buffer
 * @param	[in]	in		URL-strings
 * @retval	*p			host-strings
 * @retval	*"\0"			error
 */
/*------------------------------------------------------------------------------*/
char * func_cut_host( struct xx_url_t *buf, const char * in )
{
    static	char	*blank = "\0";
    int	err;
    char	*p;

    // check argument
    if ( buf != NULL && in != NULL ){

        // check buffer overflow
        if ( sizeof(buf->str) > strlen(in) ) {

            // get 2nd part.
            //     ex:"http://www.a.b.c/cgi/jobs.cgi?h=99&z=3" -> www.a.b.c
            //     ex:"file:///tmp/test.txt" -> tmp
            err = sscanf( in, "%*[^/]%*[/]%[^/]", buf->str);
            if ( 1 == err ) {
                p = buf->str;
            } else {
                // sscanf error
                p = blank;
            }
        }else {
            // buffer overflow
            p = blank;
        }
    }else {
        // invalid argument
        p = blank;
    }
    return p;
}


JNIEXPORT jstring JNICALL
Java_com_example_jni222_PolymorphicWebService_dnsQueryQoS(JNIEnv *env, jclass clazz, jstring urls) {


    clock_t start = clock();

    const char *urls_c_str = (*env)->GetStringUTFChars(env, urls, 0);

    ares_channel channel;
    int c, i, optmask = ARES_OPT_FLAGS, dnsclass = C_IN, type = T_A;
    int status, nfds, count;
    int use_ptr_helper = 0;
    struct ares_options options;
    struct hostent *hostent;
    fd_set read_fds, write_fds;
    struct timeval *tvp, tv;
    struct ares_addr_node *srvr, *servers = NULL;

#ifdef USE_WINSOCK
    WORD wVersionRequested = MAKEWORD(USE_WINSOCK,USE_WINSOCK);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#endif

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS)
    {
        fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
        return err_str;
    }

//    options.udp_port = 1077;  // change port number to 53, which could be used to test if the c-ares can work well (get ip address) when the dns server does not support qod query
    options.udp_port = 53;  // change port number to 53, which could be used to test if the c-ares can work well (get ip address) when the dns server does not support qod query
    optmask |= ARES_OPT_UDP_PORT;


    options.flags = ARES_FLAG_EDNS;
    options.servers = NULL;

    options.nservers = 0;

    status = ares_init_options(&channel, &options, optmask);

    if (status != ARES_SUCCESS)
    {
        fprintf(stderr, "ares_init_options: %s\n",
                ares_strerror(status));
//        return err_str;
    }




    struct xx_url_t	buf;


    char *token, *str, *tofree;
    tofree = str = strdup(urls_c_str); // we own hostnames_c_str's memory now
    while ((token = strsep(&str, ";"))){

        char *url = token;
        char* query = token + 32;
        ares_query_with_hash(channel, query, url, dnsclass, type, callback, (void*)query);

    }


    /* Wait for all queries to complete. */
    for (;;)
    {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if (nfds == 0)
            break;
        tvp = ares_timeout(channel, NULL, &tv);
        count = select(nfds, &read_fds, &write_fds, NULL, tvp);  // select: non-blocking
        if (count < 0 && (status = SOCKERRNO) != EINVAL)
        {
            printf("select fail: %d", status);
            return err_str;
        }
        ares_process(channel, &read_fds, &write_fds);

    }


    clock_t stop = clock();
    double elapsed = (double)(stop - start) * 1000.0 / CLOCKS_PER_SEC;

    char dns_return_data[300] = {0};


    dns_return_data[0] = '\0';


    for (int j = 0; j < cnt_q; j++){

        strncat(dns_return_data, dns_qos_obj[j].name, strlen(dns_return_data)-1);
        strncat(dns_return_data, "$", strlen(dns_return_data));
        strncat(dns_return_data, dns_qos_obj[j].Ips, strlen(dns_return_data));
        strncat(dns_return_data, "$", strlen(dns_return_data));
        if (strlen(dns_qos_obj[j].QoS) != 0){
            strncat(dns_return_data, dns_qos_obj[j].QoS, strlen(dns_return_data));
            strncat(dns_return_data, "$", strlen(dns_return_data));
        }
        strncat(dns_return_data, dns_qos_obj[j].Hash_url, strlen(dns_return_data));
        dns_return_data[strlen(dns_return_data)] = '|';
    }

    cnt_q = 0;



    dns_return_data[strlen(dns_return_data)-1] = '\0'; // remove the final '|' at the end of string



    jstring dns_return_data_java = (*env)->NewStringUTF(env, (const char*)dns_return_data);


    ares_destroy(channel);

    ares_library_cleanup();

    (*env)->ReleaseStringUTFChars(env, urls, urls_c_str);



    return dns_return_data_java;
}

long long current_timestamp() {
//    gettimeofday() support to specify timezone, I use NULL, which ignore the timezone,
//    but you can specify a timezone, if need.

    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // calculate milliseconds
    // printf("milliseconds: %lld\n", milliseconds);
    return milliseconds;
}

#define BUFFER_SIZE 6
unsigned char buffer[BUFFER_SIZE] = { 0 };  // This is the buffer I have available
// char *buffer = ( char *) malloc(8);  // This is the buffer I have available
// Convert long long to byte array
void LLIntToByteArray(long long value, unsigned char* p)
{
    for (int i = 0; i < BUFFER_SIZE; i++)
    {
        p[i] = ((value >> (8 * i)) & 0XFF);
//        buffer[i] = ((value >> (8 * i)) & 0XFF);
    }
}

#define MAXLINE 100
JNIEXPORT void JNICALL
Java_com_example_jni222_PolymorphicWebService_ReportQoS(JNIEnv *env, jclass clazz, jstring hash_url,
                                              jint latency) {

    const char *hashURL_c_str = (*env)->GetStringUTFChars(env, hash_url, 0);
    long int lat = (long int)latency;

    long long timestamp = current_timestamp();

    unsigned char *data = (unsigned char *) malloc(100);

    unsigned char *p = data;

    memcpy(data, hashURL_c_str, strlen(hashURL_c_str));
    DNS__SET32BIT(data + strlen(hashURL_c_str), lat);
    LLIntToByteArray(timestamp, data + strlen(hashURL_c_str) + 4);


    struct ares_addr_node *servers = NULL;

    // we assume the channel used in this library is same each time
    ares_channel channel;

    int ret = ares_init(&channel);

    if (ret != ARES_SUCCESS){
        assert("ares_init fail\n");
    }

    ret = ares_get_servers(channel, &servers);
    if (ret != ARES_SUCCESS){
        assert("ares_get_servers fail\n");
    }

    char* ip = inet_ntoa(servers->addr.addr4); //

    int sockfd;
    struct sockaddr_in	 servaddr;
    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(66666);
//    servaddr.sin_addr.s_addr = servers->addr.addr4.s_addr;
    servaddr.sin_addr.s_addr = inet_addr("192.168.1.1");
//    servaddr.sin_addr.s_addr = inet_addr("192.168.1.120");

    __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "report qos");


    int status = sendto(sockfd, (const char *)p, strlen(hashURL_c_str)+sizeof(long int)+BUFFER_SIZE,
                        MSG_CONFIRM, (const struct sockaddr *) &servaddr,
                        sizeof(servaddr));

    if (status == -1){
        assert("sendto fail\n");
    }

//    char buffer2[MAXLINE];
//
//    int len;
//    int n = recvfrom(sockfd, (char *)buffer2, MAXLINE,
//                 MSG_WAITALL, (struct sockaddr *) &servaddr,
//                 &len);
//    buffer2[n] = '\0';
//    __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "buffer2: %s", buffer2);

    free(data);

    close(sockfd);

    (*env)->ReleaseStringUTFChars(env, hash_url, hashURL_c_str);

}

JNIEXPORT jstring JNICALL
Java_com_example_jni222_PolymorphicWebService_getiphyhostname_1our(JNIEnv *env, jclass clazz,
                                                         jstring hostname) {
    // TODO: implement getiphyhostname_our()

//    const char *urls_c_str = (*env)->GetStringUTFChars(env, urls, 0);
    clock_t start = clock();


    const char *nativeString_hostname = (*env)->GetStringUTFChars(env, hostname, 0);

    ares_channel channel;
    int c, i, optmask = ARES_OPT_FLAGS, dnsclass = C_IN, type = T_A;
    int status, nfds, count;
    int use_ptr_helper = 0;
    struct ares_options options;
    struct hostent *hostent;
    fd_set read_fds, write_fds;
    struct timeval *tvp, tv;
    struct ares_addr_node *srvr, *servers = NULL;

#ifdef USE_WINSOCK
    WORD wVersionRequested = MAKEWORD(USE_WINSOCK,USE_WINSOCK);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#endif

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS)
    {
        fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
//        return err_str;
    }

//    options.udp_port = 1077;  // change port number to 53, which could be used to test if the c-ares can work well (get ip address) when the dns server does not support qod query
    options.udp_port = 53;  // change port number to 53, which could be used to test if the c-ares can work well (get ip address) when the dns server does not support qod query
    optmask |= ARES_OPT_UDP_PORT;

    options.flags = ARES_FLAG_EDNS;
    options.servers = NULL;
    options.nservers = 0;

    status = ares_init_options(&channel, &options, optmask);

    if (status != ARES_SUCCESS)
    {
        fprintf(stderr, "ares_init_options: %s\n",
                ares_strerror(status));
//        return err_str;
    }


//    struct xx_url_t	buf;

//    __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "hostnames_c_str is %s\n", urls_c_str);
//    char *token, *str, *tofree;
//    tofree = str = strdup(urls_c_str); // we own hostnames_c_str's memory now
//    while ((token = strsep(&str, ";"))){
////        __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "token is %s\n", token);
//        char *url = token;
//        char* query = func_cut_host( &buf, url);
////        ares_query_with_hash(channel, query, url, dnsclass, type, callback, (void*)query);
//
//
//
//    }


    ares_query(channel, nativeString_hostname, dnsclass, type, callback, (void*)nativeString_hostname);


    /* Wait for all queries to complete. */
    for (;;)
    {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if (nfds == 0)
            break;
        tvp = ares_timeout(channel, NULL, &tv);
        count = select(nfds, &read_fds, &write_fds, NULL, tvp);  // select: non-blocking
        if (count < 0 && (status = SOCKERRNO) != EINVAL)
        {
            printf("select fail: %d", status);
//            return err_str;
        }
        ares_process(channel, &read_fds, &write_fds);

    }
//     dns_return data format : hostname$ip11-ip12-ip1n$c,l,r | hostname$ip21-ip22-ip2n$c,l,r
    char dns_return_data[300] = {0};
//    char dns_return_data[300] = "api.openweathermap.org$192.241.167.16$|api.weatherbit.io$158.69.116.36$|weather.visualcrossing.com$44.197.34.86$";

    dns_return_data[0] = '\0';

//    __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "cnt_q: %d", cnt_q);

    for (int j = 0; j < 1; j++){
//        __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "name: %s, Ips: %s", dns_qos_objects[j].name, dns_qos_objects[j].Ips);
//        __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "name: %s, Ips: %s, QoS: %s", dns_qos_obj[j].name, dns_qos_obj[j].Ips, dns_qos_obj[j].QoS);
        strncat(dns_return_data, dns_qos_obj[j].name, strlen(dns_return_data)-1);
        strncat(dns_return_data, "$", strlen(dns_return_data));
        strncat(dns_return_data, dns_qos_obj[j].Ips, strlen(dns_return_data));
        strncat(dns_return_data, "$", strlen(dns_return_data));
        if (strlen(dns_qos_obj[j].QoS) != 0){
            strncat(dns_return_data, dns_qos_obj[j].QoS, strlen(dns_return_data));
            strncat(dns_return_data, "$", strlen(dns_return_data));
        }
        strncat(dns_return_data, dns_qos_obj[j].Hash_url, strlen(dns_return_data));
        dns_return_data[strlen(dns_return_data)] = '|';
    }

//    strncat(dns_return_data, dns_qos_obj[0].Ips, strlen(dns_return_data));



    dns_return_data[strlen(dns_return_data)-1] = '\0'; // remove the final '|' at the end of string

    __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "dns_return_data: Ips: %s", dns_return_data);

//    strncat(dns_return_data, "$", strlen(dns_return_data));

    clock_t stop = clock();
    float elapsed = (float )(stop - start) * 1000.0 / CLOCKS_PER_SEC;
    __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "Post-Process Time elapsed in ms: %f", elapsed);
//
//    char c_tmp[50] = {0}; //size of the number
//    sprintf(c_tmp, "%g", elapsed);
//
//    strncat(dns_return_data, c_tmp, strlen(dns_return_data));

    jstring dns_return_data_java = (*env)->NewStringUTF(env, (const char*)dns_return_data);


    ares_destroy(channel);

    ares_library_cleanup();


    (*env)->ReleaseStringUTFChars(env, hostname, nativeString_hostname);



    return dns_return_data_java;



}




JNIEXPORT jstring JNICALL
Java_com_example_jni222_PolymorphicWebService_dnsQueryQoS_1single(JNIEnv *env, jclass clazz,
                                                        jstring urls) {
    // TODO: implement dnsQueryQoS_single()
    clock_t start = clock();
    const char *urls_c_str = (*env)->GetStringUTFChars(env, urls, 0);


    int  status, dnsclass = C_IN, type = T_A;
    int nfds, count;
    fd_set read_fds, write_fds;
    struct timeval *tvp, tv;
    struct xx_url_t	buf;

//    __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "hostnames_c_str is %s\n", urls_c_str);
    char *token, *str, *tofree;
    tofree = str = strdup(urls_c_str); // we own hostnames_c_str's memory now


    char* query = func_cut_host( &buf, str);
    ares_query_with_hash(channel, query, str, dnsclass, type, callback, (void*)query);


    /* Wait for all queries to complete. */
    for (;;)
    {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if (nfds == 0)
            break;
        tvp = ares_timeout(channel, NULL, &tv);
        count = select(nfds, &read_fds, &write_fds, NULL, tvp);  // select: non-blocking
        if (count < 0 && (status = SOCKERRNO) != EINVAL)
        {
            printf("select fail: %d", status);
//            return err_str;
        }
        ares_process(channel, &read_fds, &write_fds);

    }
//     dns_return data format : hostname$ip11-ip12-ip1n$c,l,r | hostname$ip21-ip22-ip2n$c,l,r
    char dns_return_data[300] = {0};
//    char dns_return_data[300] = "api.openweathermap.org$192.241.167.16$|api.weatherbit.io$158.69.116.36$|weather.visualcrossing.com$44.197.34.86$";

    dns_return_data[0] = '\0';

//    __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "cnt_q: %d", cnt_q);

    for (int j = 0; j < 1; j++){
//        __android_log_print(ANDROID_LOG_VERBOSE, "MyApp", "name: %s, Ips: %s", dns_qos_objects[j].name, dns_qos_objects[j].Ips);
//        __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "name: %s, Ips: %s, QoS: %s", dns_qos_obj[j].name, dns_qos_obj[j].Ips, dns_qos_obj[j].QoS);
        strncat(dns_return_data, dns_qos_obj[j].name, strlen(dns_return_data)-1);
        strncat(dns_return_data, "$", strlen(dns_return_data));
        strncat(dns_return_data, dns_qos_obj[j].Ips, strlen(dns_return_data));
        strncat(dns_return_data, "$", strlen(dns_return_data));
        if (strlen(dns_qos_obj[j].QoS) != 0){
            strncat(dns_return_data, dns_qos_obj[j].QoS, strlen(dns_return_data));
            strncat(dns_return_data, "$", strlen(dns_return_data));
        }
        strncat(dns_return_data, dns_qos_obj[j].Hash_url, strlen(dns_return_data));
        dns_return_data[strlen(dns_return_data)] = '|';
    }

    cnt_q = 0;

    dns_return_data[strlen(dns_return_data)-1] = '\0'; // remove the final '|' at the end of string

    clock_t stop = clock();
    float elapsed = (float )(stop - start) * 1000.0 / CLOCKS_PER_SEC;
    __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "dnsQueryQoS_single Time elapsed in ms: %f", elapsed);

    jstring dns_return_data_java = (*env)->NewStringUTF(env, (const char*)dns_return_data);


//    ares_destroy(channel);

//    ares_library_cleanup();

    (*env)->ReleaseStringUTFChars(env, urls, urls_c_str);

    return dns_return_data_java;



}


#else
/* warning: ISO C forbids an empty translation unit */
typedef int dummy_make_iso_compilers_happy;
#endif




















