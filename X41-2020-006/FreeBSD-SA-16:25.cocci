// Semantic patch for https://www.freebsd.org/security/advisories/FreeBSD-SA-16:25.bspatch.asc
// spatch  --sp-file FreeBSD-SA-16:25.cocci --use-coccigrep .
@@
expression ctrl, newpos, newsize, dbz2err;
expression dpfbz2, lenread, new;
@@ 

 		/* Sanity-check */
+		if ((ctrl[0] < 0) || (ctrl[1] < 0))
+			errx(1,"Corrupt patch\n");
+
+		/* Sanity-check */
 		if(newpos+ctrl[0]>newsize)
 			errx(1,"Corrupt patch\n");

		lenread = BZ2_bzRead(&dbz2err, dpfbz2, new + newpos, ctrl[0]); 
