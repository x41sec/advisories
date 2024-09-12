#!/bin/sh
g++ main.cpp -c -fpermissive -w -I./chilkat-9.5.0-x86_64-linux-gcc/include -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fPIE -pie -fPIC -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code -ggdb -gdwarf-4
g++ -o main main.o -lpthread -lresolv -fpermissive -w ./chilkat-9.5.0-x86_64-linux-gcc/lib/libchilkat-9.5.0.a -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fPIE -pie -fPIC -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code -ggdb -gdwarf-4
