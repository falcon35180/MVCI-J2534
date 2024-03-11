CC=i686-w64-mingw32-gcc
override CFLAGS+=-static-libgcc -Wall

mvci32.dll: mvci32.o des_crypt.o des.o mvci32.def ftd2xx.h
	$(CC) $(CFLAGS) -shared -Wl,--subsystem,windows,--enable-stdcall-fixup,--kill-at -o $@ $^ -lshlwapi

mvci32.o: des_crypt.h j2534_v0404.h

des_crypt.o: des_crypt.h des.h

des.o: des.h

