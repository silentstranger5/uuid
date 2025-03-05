#include "uuid.h"

char *os_(void) {
    char *os;
    #ifdef _WIN32
        os = "windows";
        #define popen _popen
    #elif defined(__unix__)
        os = "unix";
    #endif
    return os;
}

char *strip(char *s) {
    for (char c = *s; c == ' ' || c == '\t'; c = *s++);
    return s - 1;
}

char *macaddress(void) {
    FILE *fp;
    bool eth;
    char *os = os_();
    char buffer[128];
    char *macaddr = NULL;
    char *s = NULL, *t = NULL;
    if (!strcmp(os, "windows")) {
        fp = popen("ipconfig -all", "r");
        while (fgets(buffer, 128, fp)) {
            s = buffer;
            if (isalpha(s[0])) {
                eth = !strcmp(s, "Ethernet adapter Ethernet:\n");
            } else if (s[0] != '\n') {
                s = strip(s);
                char *keyword = strtok(s, " ");
                if (eth && !strcmp(keyword, "Physical")) {
                    s = strtok(NULL, ":");
                    s = strtok(NULL, "\n") + 1;
                    macaddr = strdup(s);
                    break;
                }
            }
        }
        s = t = macaddr;
        while (*s) {
            if (*s != '-') *t++ = *s; s++;
        }
        *t++ = 0;
    } else if (!strcmp(os, "unix")) {
        fp = popen("ifconfig", "r");
        while (fgets(buffer, 128, fp)) {
            s = buffer;
            if (isalpha(s[0])) {
                eth = !strcmp(strtok(s, ":"), "eth0");
            } else if (s[0] != '\n') {
                s = strip(s);
                char *keyword = strtok(s, " ");
                if (eth && !strcmp(keyword, "ether")) {
                    s = strtok(NULL, " ");
                    macaddr = strdup(s);
                    break;
                }
            }
        }
        s = t = macaddr;
        while (*s) {
            if (*s != ':') *t++ = *s; s++;
        }
        *t++ = 0;
    }
    fclose(fp);
    return macaddr;
}

void macaddress_write(const char *filename, char *macaddr) {
    FILE *f = fopen(filename, "w");
    fwrite(macaddr, sizeof(char), strlen(macaddr), f);
    fclose(f);
}

uint64_t macaddress_read(const char *filename) {
    char *macstr;
    uint64_t addr;
    FILE *f = fopen(filename, "r");
    if (!f) {
        macstr = macaddress();
        macaddress_write(filename, macstr);
    } else {
        macstr = calloc(16, sizeof(char));
        fread(macstr, sizeof(char), 16, f);    
    }
    addr = strtoull(macstr, NULL, 16);
    free(macstr);
    return addr;
}
