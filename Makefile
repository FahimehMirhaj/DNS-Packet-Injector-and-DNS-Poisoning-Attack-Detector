# build executables named dnsinject and dnsdetect from dnsinject.c and dnsdetect.c

all:
	gcc dnsinject.c -o dnsinject -lpcap -lnet -lresolv
	gcc dnsdetect.c -o dnsdetect -lpcap -lnet -lresolv
clean:
	$(RM) dnsinject
	$(RM) dnsdetect
