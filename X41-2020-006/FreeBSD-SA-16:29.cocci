// Semantic patch for https://www.freebsd.org/security/advisories/FreeBSD-SA-16:29.bspatch.asc
// spatch  --sp-file FreeBSD-SA-16:29.cocci --use-coccigrep .
@@
expression ctrl, newpos, newsize;
expression lenread, dbz2err, dpfbz2, new;
@@


 		/* Sanity-check */
-		if ((ctrl[0] < 0) || (ctrl[1] < 0))
-			errx(1,"Corrupt patch\n");
+		if (ctrl[0] < 0 || ctrl[0] > INT_MAX ||
+		    ctrl[1] < 0 || ctrl[1] > INT_MAX)
+			errx(1, "Corrupt patch");
 
 		/* Sanity-check */
		if(newpos+ctrl[0]>newsize)
			errx(1,"Corrupt patch\n");
 
 		/* Read diff string */
 		lenread = BZ2_bzRead(&dbz2err, dpfbz2, new + newpos, ctrl[0]);
