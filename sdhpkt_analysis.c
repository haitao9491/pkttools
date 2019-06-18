/*
 * (C) Copyright 2017
 * wangxiumei <wangxiumei_ryx@163.com>
 *
 * sdhpkt_analysis.c - A description goes here.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "apfrm.h"
#include "os.h"
#include "pkt.h"
#include "misc.h"
#include "aplog.h"
#include "hash.h"
#include "hashtbl.h"

#define LINKTYPE_E1USER     0x04
#define LINKTYPE_GFP        0x71
#define LINKTYPE_LAPS       0x72
#define LINKTYPE_POS        0x73
#define LINKTYPE_ATM        0x74
#define LINKTYPE_HDLC       0x75
#define LINKTYPE_AU4        0xfc
#define LINKTYPE_E164KPPP   0xfd
#define LINKTYPE_E1LKMP     0xfe

struct pkt_seq {
	int preseq;
	int curseq;

	unsigned long long jumpcount;
	unsigned long long repeatcount;
	unsigned long long pkts;
};

struct e1user_info {
	unsigned char rsv;        /* 0x18 */
	unsigned char sel;        /* sdh forward sel */
	unsigned char linktype;   /* 0x04: E1USER */
	unsigned char slotnum;    /* slot number 1-7 */
	unsigned char chassisnum; /* chassis number, from 1 */
	unsigned char rsv1;       /* 0x00 */
	unsigned char lversion;   /* logic version */
	unsigned char devnum;     /* chassisnum: High 4bit:1~15, slot: low 4bit:1~15 */
	unsigned char inspeed;    /* srcport: bit7-bit2:1-24; srcport speed: bit1-0 */
	unsigned char stm1num;    /* stm-1 number */
	unsigned char channel;    /* e1 channel number */
	unsigned char dir;        /* direction: odd port: 0x0a; even port: 0x0b */

	struct pkt_seq pktseq;
};

struct sdh_pkt_info {
	unsigned char selB;     /* sel B */
	unsigned char selA;     /* sel A */
	unsigned char linktype; /* link type */
	unsigned char devnum;   /* chassisnum: High 4bit:1~15, slot: low 4bit:1~15 */
	unsigned char inspeed;  /* srcport: bit7-bit2:1-24; srcport speed: bit1-0 */
	unsigned char stm1num;  /* stm-1 number */
	unsigned char lversion; /* used bit7-1, bit0=0 */
	unsigned char channel;  /* task channel start number */
	unsigned char speed;    /* task channel speed */
	unsigned char rsv;          
	unsigned char channum;  /* channel count */
	unsigned char seq;      /* seq number: 0-255 */

	struct pkt_seq pktseq;
};

struct pkt_stat {
	unsigned long long gfp_pkts;
	unsigned long long laps_pkts;
	unsigned long long pos_pkts;
	unsigned long long atm_pkts;
	unsigned long long hdlc_pkts;
	unsigned long long au4_pkts;
	unsigned long long e164kppp_pkts;
	unsigned long long e1lkmp_pkts;
	unsigned long long e1user_pkts;
	unsigned long long other_pkts;
	unsigned long long pkts;             /* total pkts */
};

#define FP_OFFSET_GFP      0
#define FP_OFFSET_LAPS     1
#define FP_OFFSET_POS      2
#define FP_OFFSET_ATM      3
#define FP_OFFSET_HDLC     4
#define FP_OFFSET_AU4      5
#define FP_OFFSET_E164KPPP 6
#define FP_OFFSET_E1LKMP   7
#define FP_OFFSET_E1USER   8
#define FP_MAX_NUM         9

#define FILE_NAME_LEN      128
struct output_file_handle {
	char file[FILE_NAME_LEN];
	FILE *fp;
};

struct pkt_type_map {
	int linktype;
	char name[16];
};

#define INSPEED_155M    0
#define INSPEED_622M    1
#define INSPEED_2_5G    2
#define INSPEED_10G     3

#define TASK_SPEED_NULL    0
#define TASK_SPEED_VC11    1
#define TASK_SPEED_E1      2
#define TASK_SPEED_VC12    3
#define TASK_SPEED_34M     4
#define TASK_SPEED_45M     5
#define TASK_SPEED_VC4     6
#define TASK_SPEED_622M    7
#define TASK_SPEED_2_5G    8
#define TASK_SPEED_10G     9

struct speed_map {
	char speed[16];
};

int period = 60;
int logout = 0;
char *filename = NULL;
char *devname = NULL;

pcap_t *pcap_fp = NULL;
void *sdhht = NULL;
void *e1userht = NULL;
char *outfiledir = "/tmp/sdhpkt/";
struct pkt_stat stat;
struct output_file_handle ofp[FP_MAX_NUM];

struct pkt_type_map pkt_map_t[FP_MAX_NUM] = {
	{LINKTYPE_GFP, "GFP"},
	{LINKTYPE_LAPS, "LAPS"},
	{LINKTYPE_POS, "POS"},
	{LINKTYPE_ATM, "ATM"},
	{LINKTYPE_HDLC, "HDLC"},
	{LINKTYPE_AU4, "AU4"},
	{LINKTYPE_E164KPPP, "E164KPPP"},
	{LINKTYPE_E1LKMP, "E1LINKMAP"},
	{LINKTYPE_E1USER, "E1USER"}
};

struct speed_map inspeed_t[] = {
	{"155M"},
	{"622M"},
	{"2.5G"},
	{"10G"}
};

struct speed_map taskspeed_t[] = {
	{"NULL"},
	{"VC11"},
	{"E1"},
	{"VC12"},
	{"34M"},
	{"45M"},
	{"VC4"},
	{"622M"},
	{"2.5G"},
	{"10G"}
};

void sdhpkt_analysis_show_usage(char *progname)
{
	printf("   --file filename: read from pcap file.\n");
	printf("   --dev devname: read from ethernet device.\n");
	printf("   --period time: period time (Unit: second).\n");
	printf("   --logout: output error pkts.\n");
}

void sdhpkt_analysis_show_version(char *progname)
{
	printf("sdhpkt_analysis - V0.1\n");
}

int sdhpkt_analysis_parse_args(int argc, char **argv)
{
	int i = 0;

	while (i < argc) {
		if (strcmp(argv[i], "--file") == 0) {
			if (((i + 1) >= argc) || (argv[i + 1][0] == '-'))
				return -1;

			i++;
			filename = argv[i];
		}
		else if (strcmp(argv[i], "--dev") == 0) {
			if (((i + 1) >= argc) || (argv[i + 1][0] == '-'))
				return -1;

			i++;
			devname = argv[i];
		}
		else if (strcmp(argv[i], "--period") == 0) {
			if (((i + 1) >= argc) || (argv[i + 1][0] == '-'))
				return -1;

			i++;
			period = atoi(argv[i]);
			if (period == 0) {
				period = 60;
			}
		}
		else if (strcmp(argv[i], "--logout") == 0) {
			logout = 1;
		}
		else {
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			return -1;
		}
		i++;
	}

	return 0;
}

void sdhpkt_analysis_sigalrm_handle()
{
}

void sdhpkt_analysis_sigusr1_handle()
{
}

void sdhpkt_analysis_sigusr2_handle()
{
}

static unsigned long sdhpkt_hash(void *key, unsigned int bits)
{
	struct sdh_pkt_info *n = (struct sdh_pkt_info *)key;
	unsigned long v;

	v = (n->devnum << 24) | (n->inspeed << 16) | (n->stm1num << 8) | n->channel;

	return SDBMHashUL(v, bits);
}

static int sdhpkt_compare(void *a, void *b)
{
	struct sdh_pkt_info *ka = (struct sdh_pkt_info *)a;
	struct sdh_pkt_info *kb = (struct sdh_pkt_info *)b;

	if ((ka->linktype == kb->linktype) && 
			(ka->devnum == kb->devnum) && (ka->inspeed == kb->inspeed) 
			&& (ka->stm1num == kb->stm1num) && (ka->channel == kb->channel))
		return 0;

	return 1;
}

static unsigned long e1user_hash(void *key, unsigned int bits)
{
	struct e1user_info *n = (struct e1user_info *)key;
	unsigned long v;

	v = (n->devnum << 24) | (n->inspeed << 16) | (n->stm1num << 8) | n->channel;

	return SDBMHashUL(v, bits);
}

static int e1user_compare(void *a, void *b)
{
	struct e1user_info *ka = (struct e1user_info *)a;
	struct e1user_info *kb = (struct e1user_info *)b;

	if ((ka->devnum == kb->devnum) && (ka->inspeed == kb->inspeed)
			&& (ka->stm1num == kb->stm1num) && (ka->channel == kb->channel))
		return 0;

	return 1;
}

int sdhpkt_outfile_init()
{
	int i;
	time_t tt;
	time(&tt);
	struct tm *t = localtime(&tt);

	memset(ofp, 0, sizeof(ofp));
	for (i = 0; i < FP_MAX_NUM; i++) {
		sprintf(ofp[i].file, "%s%s%04d%02d%02d%02d%02d%02d.csv",
			outfiledir, pkt_map_t[i].name, t->tm_year+1900, t->tm_mon+1, 
			t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		ofp[i].fp = fopen(ofp[i].file, "w");
		if (ofp[i].fp == NULL) {
			return -1;
		}
	}

	return 0;
}

int sdhpkt_pcap_init()
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if (filename != NULL) {
		pcap_fp = pcap_open_offline(filename, errbuf);
		if (pcap_fp == NULL) {
			LOGERROR("failed to open file %s: %s.", filename, errbuf);
			return -1;
		}
	}
	if (devname != NULL) {
#if 0
		pcap_fp = pcap_open_live(devname, 65536, 1, 50, errbuf);
		if (pcap_fp == NULL) {
			LOGERROR("failed to open device %s: %s", devname, errbuf);
			return -1;
		}
#else
		pcap_fp = pcap_create(devname, errbuf);
		if (pcap_fp == NULL) {
			LOGERROR("failed to open device %s: %s", devname, errbuf);
			return -1;
		}
		if (pcap_set_snaplen(pcap_fp, 65536) < 0) {
			LOGERROR("failed to set pcap snaplen");
			return -1;
		}
		if (pcap_set_promisc(pcap_fp, 1) < 0) {
			LOGERROR("failed to set pcap promisc");
			return -1;
		}
		if (pcap_set_timeout(pcap_fp, 1000) < 0) {
			LOGERROR("failed to set pcap timeout");
			return -1;
		}
		if (pcap_set_buffer_size(pcap_fp, 16*1024*1024) < 0) {
			LOGERROR("failed to set pcap buffersize.");
			return -1;
		}
		if (pcap_activate(pcap_fp) < 0) {
			LOGERROR("failed to set pcap activate.");
			return -1;
		}
#endif
	}

	return 0;
}

void sdhpkt_analysis_exit_env()
{
	int i = 0;

	if (pcap_fp) {
		pcap_close(pcap_fp);
		pcap_fp = NULL;
	}
	if (e1userht) {
		hashtbl_close(e1userht);
		e1userht = NULL;
	}
	if (sdhht) {
		hashtbl_close(sdhht);
		sdhht = NULL;
	}
	for (i = 0; i < FP_MAX_NUM; i++) {
		if (ofp[i].fp != NULL) {
			fclose(ofp[i].fp);
			ofp[i].fp = NULL;
		}
	}
}

int sdhpkt_analysis_init_env()
{
	if (filename != NULL && devname != NULL) {
		LOGERROR("Can't both read from ethernet device and file at the same time.");
		return -1;
	}
	if (filename == NULL && devname == NULL) {
		LOGERROR("please input read filename or devname.");
		return -1;
	}

	sdhht = hashtbl_open(0x80000, sdhpkt_hash, sdhpkt_compare, NULL, "SDH.HT");
	if (sdhht == NULL) {
		LOGERROR("failed to open sdh hashtable.");
		goto init_env_failed;
	}

	e1userht = hashtbl_open(0x8000, e1user_hash, e1user_compare, NULL, "E1USER.HT");
	if (e1userht == NULL) {
		LOGERROR("failed to open e1user hashtable.");
		goto init_env_failed;
	}

	if (sdhpkt_outfile_init() != 0) {
		LOGERROR("failed to init outfile.");
		goto init_env_failed;
	}

	if (sdhpkt_pcap_init() != 0) {
		LOGERROR("pcap init failed.");
		goto init_env_failed;
	}
	return 0;

init_env_failed:
	sdhpkt_analysis_exit_env();
	return -1;
}

void sdhpkt_analysis_log()
{
	LOG("STAT: TOTAL_PKTS: %llu; GFP: %llu; LAPS: %llu; POS: %llu; ATM: %llu; HDLC: %llu; AU4: %llu; E164KPPP: %llu; E1LKMP: %llu; E1USER: %llu; OTH: %llu",
			stat.pkts, stat.gfp_pkts, stat.laps_pkts, stat.pos_pkts, stat.atm_pkts, stat.hdlc_pkts,
			stat.au4_pkts, stat.e164kppp_pkts, stat.e1lkmp_pkts, stat.e1user_pkts, stat.other_pkts);
}

void sdhpkt_analysis_sdh_output(void *key, void *value, void *arg)
{
	struct sdh_pkt_info *info = (struct sdh_pkt_info *)key;
	int type = 0;

	if (key == NULL)
		return;
	
	if (info->linktype == LINKTYPE_GFP) {
		type = FP_OFFSET_GFP;
	}
	else if (info->linktype == LINKTYPE_LAPS) {
		type = FP_OFFSET_LAPS;
	}
	else if (info->linktype == LINKTYPE_POS) {
		type = FP_OFFSET_POS;
	}
	else if (info->linktype == LINKTYPE_ATM) {
		type = FP_OFFSET_ATM;
	}
	else if (info->linktype == LINKTYPE_HDLC) {
		type = FP_OFFSET_HDLC;
	}
	else if (info->linktype == LINKTYPE_AU4) {
		type = FP_OFFSET_AU4;
	}
	else if (info->linktype == LINKTYPE_E164KPPP) {
		type = FP_OFFSET_E164KPPP;
	}
	else if (info->linktype == LINKTYPE_E1LKMP) {
		type = FP_OFFSET_E1LKMP;
	}
	else {
		return;
	}

	fprintf(ofp[type].fp, "0x%02x,0x%02x,0x%02x,%d,%d,%d,%s,%d,0x%02x,%d,%d(%s),%d,%llu,%llu,%llu\n", 
			info->selB, info->selA, info->linktype, (info->devnum >> 4) & 0xf, info->devnum & 0xf,
			(info->inspeed >> 2) & 0x3f, inspeed_t[info->inspeed & 0x3].speed, info->stm1num, info->lversion, 
			info->channel, info->speed, taskspeed_t[info->speed].speed, info->channum, info->pktseq.pkts, 
			info->pktseq.jumpcount, info->pktseq.repeatcount);
}

void sdhpkt_analysis_e1user_output(void *key, void *value, void *arg)
{
	struct e1user_info *info = (struct e1user_info *)key;

	if (key == NULL)
		return;

	fprintf(ofp[FP_OFFSET_E1USER].fp, "0x%02x,0x%02x,%d,%d,0x%02x,%d,%d,%d,%d(%s),%d,%d,0x%02x,%llu,%llu,%llu\n", 
			info->sel, info->linktype, info->slotnum, info->chassisnum, info->lversion,
			(info->devnum >> 4) & 0xf, info->devnum & 0xf, (info->inspeed >> 2) & 0x3f, 
			info->inspeed & 0x3, inspeed_t[info->inspeed & 0x3].speed, info->stm1num, info->channel, info->dir, 
			info->pktseq.pkts, info->pktseq.jumpcount, info->pktseq.repeatcount);
}

void sdhpkt_analysis_output_tofile()
{
	int i = 0;

	for (i = 0; i < FP_MAX_NUM; i++) {
		if (ofp[i].fp && (i != FP_OFFSET_E1USER)) {
			fprintf(ofp[i].fp, "SELB,SELA,TYPE,HCHASSIS,HSLOT,SRCPORT,SRCSPEED,STM1,LVER,CHNUM,CHSPEED,CHCOUNT,PKTS,JUMP,REPEAT\n");
		}
	}
	if (ofp[FP_OFFSET_E1USER].fp) {
		fprintf(ofp[FP_OFFSET_E1USER].fp, "SEL,TYPE,SLOT,CHASSIS,LVER,HCHASSIS,HSLOT,SRCPORT,SRCSPEED,STM1,E1NUM,DIR,PKTS,JUMP,REPEAT\n");
	}

	hashtbl_traverse(sdhht, sdhpkt_analysis_sdh_output, NULL);
	hashtbl_traverse(e1userht, sdhpkt_analysis_e1user_output, NULL);
}

int sdhpkt_analysis_e1userpkt_process(int linktype, struct pcap_pkthdr *pcaphdr, unsigned char *pcapdata)
{
	struct e1user_info *info = NULL, kinfo;

	if (!pcaphdr || !pcapdata)
		return -1;

	memcpy(&kinfo, pcapdata, 12);
	info = (struct e1user_info *)hashtbl_find(e1userht, &kinfo, NULL);
	if (info != NULL) {
		info->pktseq.preseq = info->pktseq.curseq;
		info->pktseq.curseq = pcapdata[15];
		if ((info->pktseq.preseq == 255 && info->pktseq.curseq == 0) ||
				((info->pktseq.preseq + 1) == info->pktseq.curseq)) {
			info->pktseq.pkts++;
			return 0;
		}
		if (info->pktseq.preseq == info->pktseq.curseq) {
			info->pktseq.repeatcount++;
			info->pktseq.pkts++;
			if (logout == 1) {
				LGWR(pcapdata, pcaphdr->caplen, "E1USER_REPEAT:");
			}
			return 0;
		}
		if ((info->pktseq.preseq + 1) != info->pktseq.curseq) {
			info->pktseq.jumpcount++;
			info->pktseq.pkts++;
			if (logout == 1) {
				LGWR(pcapdata, pcaphdr->caplen, "E1USER_JUMP: %d:%d", 
						info->pktseq.preseq, info->pktseq.curseq);
			}
			return 0;
		}
		LOGERROR("E1USER: can't to here, why????");
		return -1;
	}

	info = (struct e1user_info *)malloc(sizeof(struct e1user_info));
	if (info == NULL) {
		LOGERROR("e1user_info malloc failed.");
		return -1;
	}
	memcpy(info, pcapdata, 12);
	info->pktseq.preseq = 0xffffffff;
	info->pktseq.curseq = pcapdata[15];
	info->pktseq.jumpcount = 0;
	info->pktseq.repeatcount = 0;
	info->pktseq.pkts = 1;
	if (hashtbl_insert(e1userht, info, info) < 0) {
		LOGERROR("E1USERHT: insert failed.");
		free(info);
		return -1;
	}

	return 0;
}

int sdhpkt_analysis_pkt_process(int linktype, struct pcap_pkthdr *pcaphdr, unsigned char *pcapdata)
{
	struct sdh_pkt_info *info = NULL, kinfo;

	if (!pcaphdr || !pcapdata)
		return -1;

	memcpy(&kinfo, pcapdata, 12);
	info = (struct sdh_pkt_info *)hashtbl_find(sdhht, &kinfo, NULL);
	if (info != NULL) {
		info->pktseq.preseq = info->pktseq.curseq;
		info->pktseq.curseq = kinfo.seq;
		if ((info->pktseq.preseq == 255 && info->pktseq.curseq == 0) ||
				((info->pktseq.preseq + 1) == info->pktseq.curseq)) {
			info->pktseq.pkts++;
			return 0;
		}
		if (info->pktseq.preseq == info->pktseq.curseq) {
			info->pktseq.repeatcount++;
			info->pktseq.pkts++;
			if (logout == 1) {
				LGWR(pcapdata, pcaphdr->caplen, "%s_REPEAT:", pkt_map_t[linktype].name);
			}
			return 0;
		}
		if ((info->pktseq.preseq + 1) != info->pktseq.curseq) {
			info->pktseq.jumpcount++;
			info->pktseq.pkts++;
			if (logout == 1) {
				LGWR(pcapdata, pcaphdr->caplen, "%s_JUMP: %d:%d", pkt_map_t[linktype].name,
						info->pktseq.preseq, info->pktseq.curseq);
			}
			return 0;
		}
		LOGERROR("%s: can't to here, why????", pkt_map_t[linktype].name);
		return -1;
	}

	info = (struct sdh_pkt_info *)malloc(sizeof(struct sdh_pkt_info));
	if (info == NULL) {
		LOGERROR("sdk_pkt_info: %s malloc failed.", pkt_map_t[linktype].name);
		return -1;
	}
	memcpy(info, pcapdata, 12);
	info->pktseq.preseq = 0xffffffff;
	info->pktseq.curseq = kinfo.seq;
	info->pktseq.jumpcount = 0;
	info->pktseq.repeatcount = 0;
	info->pktseq.pkts = 1;
	if (hashtbl_insert(sdhht, info, info) < 0) {
		LOGERROR("%s: insert failed.", pkt_map_t[linktype].name);
		free(info);
		return -1;
	}

	return 0;
}

int sdhpkt_analysis_process()
{
	struct sdh_pkt_info *pmsg = NULL;
	struct pcap_pkthdr *pcaphdr = NULL;
	unsigned char *pcapdata = NULL;
	int rc = 0;

	if (pcap_fp == NULL) {
		return -1;
	}

	rc = pcap_next_ex(pcap_fp, &pcaphdr, (const u_char **)&pcapdata);
	if (rc == 1) {
		pmsg = (struct sdh_pkt_info *)pcapdata;
		if (pmsg->linktype == LINKTYPE_GFP) {
			sdhpkt_analysis_pkt_process(FP_OFFSET_GFP, pcaphdr, pcapdata);
			stat.gfp_pkts++;
		}
		else if (pmsg->linktype == LINKTYPE_LAPS) {
			sdhpkt_analysis_pkt_process(FP_OFFSET_LAPS, pcaphdr, pcapdata);
			stat.laps_pkts++;
		}
		else if (pmsg->linktype == LINKTYPE_POS) {
			sdhpkt_analysis_pkt_process(FP_OFFSET_POS, pcaphdr, pcapdata);
			stat.pos_pkts++;
		}
		else if (pmsg->linktype == LINKTYPE_ATM) {
			sdhpkt_analysis_pkt_process(FP_OFFSET_ATM, pcaphdr, pcapdata);
			stat.atm_pkts++;
		}
		else if (pmsg->linktype == LINKTYPE_HDLC) {
			sdhpkt_analysis_pkt_process(FP_OFFSET_HDLC, pcaphdr, pcapdata);
			stat.hdlc_pkts++;
		}
		else if (pmsg->linktype == LINKTYPE_AU4) {
			sdhpkt_analysis_pkt_process(FP_OFFSET_AU4, pcaphdr, pcapdata);
			stat.au4_pkts++;
		}
		else if (pmsg->linktype == LINKTYPE_E164KPPP) {
			sdhpkt_analysis_pkt_process(FP_OFFSET_E164KPPP, pcaphdr, pcapdata);
			stat.e164kppp_pkts++;
		}
		else if (pmsg->linktype == LINKTYPE_E1LKMP) {
			sdhpkt_analysis_pkt_process(FP_OFFSET_E1LKMP, pcaphdr, pcapdata);
			stat.e1lkmp_pkts++;
		}
		else if (pmsg->linktype == LINKTYPE_E1USER) {
			sdhpkt_analysis_e1userpkt_process(FP_OFFSET_E1USER, pcaphdr, pcapdata);
			stat.e1user_pkts++;
		}
		else {
			if (logout == 1) {
				LGWR(pcapdata, pcaphdr->caplen, "OTH_PKT:");
			}
			stat.other_pkts++;
		}
		stat.pkts++;
	}
	else {
		if (rc == 0) {
			LOG("timeout expired."); 
			return 1;
		}
		else if (rc == -2) {
			LOG("no more packets.");
			return 2;
		}
		else {
			return -1;
		}
	}

	return -1;
}

int sdhpkt_analysis_run(long instance, unsigned long data)
{
	struct timeval t;
	unsigned int prev = 0;
	int rc = 0;

	if (sdhpkt_analysis_init_env() < 0)
		return -1;

	while (ap_is_running()) {
		rc = sdhpkt_analysis_process();
		if (rc == 2)
			break;

		gettimeofday(&t, NULL);
		if (((unsigned int)t.tv_sec != prev) && 
			((unsigned int)t.tv_sec % 30) == 0) {
			sdhpkt_analysis_log();
			prev = (unsigned int)t.tv_sec;
		}
	}

	sdhpkt_analysis_output_tofile();
	sdhpkt_analysis_log();
	sdhpkt_analysis_exit_env();

	return 0;
}

static struct ap_framework sdhpkt_analysis_app = {
	NULL,
	sdhpkt_analysis_run,
	0,
	sdhpkt_analysis_sigalrm_handle,
	sdhpkt_analysis_sigusr1_handle,
	sdhpkt_analysis_sigusr2_handle,
	sdhpkt_analysis_show_usage,
	sdhpkt_analysis_show_version,
	sdhpkt_analysis_parse_args
};

#if defined(__cplusplus)
extern "C" {
#endif

struct ap_framework *register_ap(void)
{
	return &sdhpkt_analysis_app;
}

#if defined(__cplusplus)
}
#endif

