#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include <libgen.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <pwd.h>

#define KEYDIR "/etc/ssh-public-keys.d"

/*
 * Check if a given keyfile is secure. A keyfile is considered unsecure if
 * it is not owned by the user or by root. It is also unsecure if the
 * keyfile is writeable by group or other.
 *
 * The same check will be done for every parent directory. If a
 * parentdirectory would be writeable by an attacker, this user would be
 * able to replace the keyfile or the whole directory tree with a custom
 * version.
 *
 * Returns 0 on success and -1 on failure
 */
int is_keyfile_secure(int fd, uid_t uid, const char *filename, char *err, size_t errlen) {
  struct stat st;
  struct passwd* owner;
  char* parentdir;
  char path[PATH_MAX];

  if(realpath(filename, path) == NULL) {
    snprintf(err, errlen, "realpath %s failed: %s", filename, strerror(errno));
    return -1;
  }

  if(fstat(fd, &st) < 0) {
    snprintf(err, errlen, "cannot stat file %s: %s", path, strerror(errno));
    return -1;
  }

  if(!S_ISREG(st.st_mode)) {
    snprintf(err, errlen, "%s is not a regular file", path);
    return -1;
  }

  if(st.st_uid != 0 && st.st_uid != uid) {
    if((owner = getpwuid(st.st_uid)) != NULL)
      snprintf(err, errlen, "%s is owned by unexpected user %s", path, owner->pw_name);
    else
      snprintf(err, errlen, "%s is owned by unknown user %u", path, st.st_uid);

    return -1;
  }
  if((st.st_mode & 022) != 0) {
    snprintf(err, errlen, "%s should only be writeable by the owner itself (mode=%03o)", path, st.st_mode & 07777);
    return -1;
  }

  /* now check all leading directories until we reach the root directory */
  for(;;) {
    if((parentdir = dirname(path)) == NULL) {
      snprintf(err, errlen, "dirname(%s) failed", filename);
      return -1;
    }

    /* make sure we set path to the new parent directory so it will use
     * that as the base for the next interation */
    strncpy(path, parentdir, sizeof(path)-1);
    path[sizeof path - 1] = '\0';

    if(stat(parentdir, &st) < 0) {
      snprintf(err, errlen, "unable to stat directory %s", parentdir);
      return -1;
    }
    else if(st.st_uid !=0 && st.st_uid != uid) {
      snprintf(err, errlen, "bad ownership for directory %s", parentdir);
      return -1;
    }
    else if((st.st_mode & 022) != 0) {
      snprintf(err, errlen, "bad mode (0%3o) for directory %s", st.st_mode & 07777, parentdir);
      return -1;
    }

    if((strcmp(parentdir, "/") == 0) || (strcmp(parentdir, ".") == 0))
      break;
  }
  return 0;
}

void cat(int fd) {
  char buffer[1024];
  ssize_t nbytes;

  while((nbytes = read(fd, buffer, sizeof(buffer))) > 0) {
    write(1, buffer, nbytes);
  }
}

void usage(void) {
  fprintf(stderr,
    "usage: authorized_keys <user>\n"
    "\n"
    "retrieve the public keys of the specified user\n"
    "\n"
    "the intention of this script is to be used as an AuthorizedKeysCommand\n"
    "by the ssh daemon. It will retrieve the public key file of the specified\n"
    "user from "KEYDIR". If no key can be found it will return with a zero\n"
    "exitcode. If a key can be found it will be printed to stdout\n");
}

int main(int argc, char** argv) {
  char* username;

  struct passwd* user;
  char keyfile[PATH_MAX];
  char error[1024];
  int fd;

  if(argc > 1) {
    username = argv[1];
  }
  else {
    usage();
    return 0;
  }

  user = getpwnam(username);
  if(user == NULL) {
    fprintf(stderr, "authorized_keys: user %s could not be found\n", username);
    return 1;
  }

  snprintf(keyfile, PATH_MAX, "%s/%s.pub", KEYDIR, user->pw_name);

  if((fd = open(keyfile, O_NOFOLLOW | O_RDONLY)) == -1) {
    /* if there is no file or we cannot open it, make sure we do not fail and
     * openssh can continue with the normal authorized_keys behaviour */
    return 0;
  }

  if(is_keyfile_secure(fd, user->pw_uid, keyfile, error, sizeof(error)) == 0) {
    cat(fd);
    close(fd);
  }
  else {
    fprintf(stderr, "authorized_keys: %s\n", error);
    close(fd);
    return -1;
  }

  return 0;
}
