/*
 * ccHTTPd is distributed under the following license:
 *
 * Copyright (c) 2008,2023 Steffen Wendzel <steffen (at) wendzel (dot) de> All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software must display the following acknowledgement: This product includes software developed by the <copyright holder>.
 * 4. Neither the name of the <copyright holder> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */


typedef struct {
	char *suffix;
	char *mime_name;
} mime_types_t;

char text_plain[] = "text/plain";
char text_html[] = "text/html";

/* put html stuff ant the like on the top of the list */
/* this mime list is based on debian etc/mime.types */

mime_types_t mime_types [] = {
	/* very frequently requested stuff */
	{ "xhtml", "application/xhtml+xml" },
	{ "xht", "application/xhtml+xml" },
	{ "html", "text/html" },
	{ "htm", "text/html" },
	{ "shtml", "text/html" },
	{ "js", "application/x-javascript" },
	{ "asc", "text/plain" },
	{ "txt", "text/plain" },
	{ "text", "text/plain" },
	{ "xml", "application/xml" },
	{ "css", "text/css" },
	{ "xsl", "application/xml" },
	
	/* catch c modules */
	{ "cm", "text/html" },
	
	/* also frequently requested (audio files and the like) */
	{ "pdf", "application/pdf" },
	{ "mp2", "audio/mpeg" },
	{ "mp3", "audio/mpeg" },
	{ "m3u", "audio/mpegurl" },
	{ "ogg", "application/ogg" },
	{ "wma", "audio/x-ms-wma" },
	{ "jar", "application/java-archive" },
	{ "class", "application/java-vm" },
	{ "zip", "application/zip" },
	{ "sh", "application/x-sh" },
	{ "shar", "application/x-shar" },
	{ "swf", "application/x-shockwave-flash" },
	{ "swfl", "application/x-shockwave-flash" },
	{ "gtar", "application/x-gtar" },
	{ "tgz", "application/x-gtar" },
	{ "taz", "application/x-gtar" },
	{ "wmv", "video/x-ms-wmv" },
	{ "mpeg", "video/mpeg" },
	{ "mpg", "video/mpeg" },
	{ "mpe", "video/mpeg" },
	{ "mp4", "video/mp4" },
	{ "qt", "video/quicktime" },
	{ "mov", "video/quicktime" },
	{ "gif", "image/gif" },
	{ "jpeg", "image/jpeg" },
	{ "jpg", "image/jpeg" },
	{ "png", "image/png" },
	{ "svg", "image/svg+xml" },
	{ "svgz", "image/svg+xml" },
	{ "tiff", "image/tiff" },
	{ "asf", "video/x-ms-asf" },
	
	/* not so frequently requested */
	{ "ez", "application/andrew-inset" },
	{ "atom", "application/atom+xml" },
	{ "atomcat", "application/atomcat+xml" },
	{ "atomsrv", "application/atomserv+xml" },
	{ "cap", "application/cap" },
	{ "pcap", "application/cap" },
	{ "cu", "application/cu-seeme" },
	{ "davmount", "application/davmount+xml" },
	{ "tsp", "application/dsptype" },
	{ "spl", "application/futuresplash" },
	{ "hta", "application/hta" },
	{ "ser", "application/java-serialized-object" },
	{ "m3g", "application/m3g" },
	{ "hqx", "application/mac-binhex40" },
	{ "cpt", "application/mac-compactpro" },
	{ "nb", "application/mathematica" },
	{ "nbp", "application/mathematica" },
	{ "mdb", "application/msaccess" },
	{ "doc", "application/msword" },
	{ "dot", "application/msword" },
	{ "bin", "application/octet-stream" },
	{ "oda", "application/oda" },
	{ "ogm", "application/ogg" },
	{ "key", "application/pgp-keys" },
	{ "pgp", "application/pgp-signature" },
	{ "prf", "application/pics-rules" },
	{ "ps", "application/postscript" },
	{ "ai", "application/postscript" },
	{ "eps", "application/postscript" },
	{ "espi", "application/postscript" },
	{ "rar", "application/rar" },
	{ "rdf", "application/rdf+xml" },
	{ "rss", "application/rss+xml" },
	{ "rtf", "application/rtf" },
	{ "smi", "application/smil" },
	{ "smil", "application/smil" },
	{ "wpd", "application/wordperfect" },
	{ "wp5", "application/wordperfect5.1" },
	{ "xspf", "application/xspf+xml" },
	{ "cdy", "application/vnd.cinderella" },
	{ "kml", "application/vnd.google-earth.kml+xml" },
	{ "kmz", "application/vnd.google-earth.kmz" },
	{ "xul", "application/vnd.mozilla.xul+xml" },
	{ "xls", "application/vnd.ms-excel" },
	{ "xlb", "application/vnd.ms-excel" },
	{ "xlt", "application/vnd.ms-excel" },
	{ "cat", "application/vnd.ms-pki.seccat" },
	{ "stl", "application/vnd.ms-pki.stl" },
	{ "ppt", "application/vnd.ms-powerpoint" },
	{ "pps", "application/vnd.ms-powerpoint" },
	{ "odc", "application/vnd.oasis.opendocument.chart" },
	{ "odb", "application/vnd.oasis.opendocument.database" },
	{ "odf", "application/vnd.oasis.opendocument.formula" },
	{ "odg", "application/vnd.oasis.opendocument.graphics" },
	{ "otg", "application/vnd.oasis.opendocument.graphics-template" },
	{ "odi", "application/vnd.oasis.opendocument.image" },
	{ "odp", "application/vnd.oasis.opendocument.presentation" },
	{ "otp", "application/vnd.oasis.opendocument.presentation-template" },
	{ "ods", "application/vnd.oasis.opendocument.spreadsheet" },
	{ "ots", "application/vnd.oasis.opendocument.spreadsheet-template" },
	{ "odt", "application/vnd.oasis.opendocument.text" },
	{ "odm", "application/vnd.oasis.opendocument.text-master" },
	{ "ott", "application/vnd.oasis.opendocument.text-template" },
	{ "oth", "application/vnd.oasis.opendocument.text-web" },
	{ "cod", "application/vnd.rim.cod" },
	{ "mmf", "application/vnd.smaf" },
	{ "sdc", "application/vnd.stardivision.calc" },
	{ "sds", "application/vnd.stardivision.chart" },
	{ "sda", "application/vnd.stardivision.draw" },
	{ "sdd", "application/vnd.stardivision.impress" },
	{ "sdf", "application/vnd.stardivision.math" },
	{ "sdw", "application/vnd.stardivision.writer" },
	{ "sgl", "application/vnd.stardivision.writer-global" },
	{ "sxc", "application/vnd.sun.xml.calc" },
	{ "stc", "application/vnd.sun.xml.calc.template" },
	{ "sxd", "application/vnd.sun.xml.draw" },
	{ "std", "application/vnd.sun.xml.draw.template" },
	{ "sxi", "application/vnd.sun.xml.impress" },
	{ "sti", "application/vnd.sun.xml.impress.template" },
	{ "sxm", "application/vnd.sun.xml.math" },
	{ "sxw", "application/vnd.sun.xml.writer" },
	{ "sxg", "application/vnd.sun.xml.writer.global" },
	{ "stw", "application/vnd.sun.xml.writer.template" },
	{ "sis", "application/vnd.symbian.install" },
	{ "vsd", "application/vnd.visio" },
	{ "wbxml", "application/vnd.wap.wbxml" },
	{ "wmlc", "application/vnd.wap.wmlc" },
	{ "wmlsc", "application/vnd.wap.wmlscriptc" },
	{ "wk", "application/x-123" },
	{ "7z", "application/x-7z-compressed" },
	{ "abw", "application/x-abiword" },
	{ "dmg", "application/x-apple-diskimage" },
	{ "bcpio", "application/x-bcpio" },
	{ "torrent", "application/x-bittorrent" },
	{ "cab", "application/x-cab" },
	{ "cbr", "application/x-cbr" },
	{ "cbz", "application/x-cbz" },
	{ "cdf", "application/x-cdf" },
	{ "vcd", "application/x-cdlink" },
	{ "pgn", "application/x-chess-pgn" },
	{ "cpio", "application/x-cpio" },
	{ "csh", "application/x-csh" },
	{ "deb", "application/x-debian-package" },
	{ "udeb", "application/x-debian-package" },
	{ "dcr", "application/x-director" },
	{ "dir", "application/x-director" },
	{ "dxr", "application/x-director" },
	{ "dms", "application/x-dms" },
	{ "wad", "application/x-doom" },
	{ "dvi", "application/x-dvi" },
	{ "rhtml", "application/x-httpd-eruby" },
	{ "flac", "application/x-flac" },
	{ "pfa", "application/x-font" },
	{ "pfb", "application/x-font" },
	{ "gsf", "application/x-font" },
	{ "pcf", "application/x-font" },
	{ "mm", "application/x-freemind" },
	{ "spl", "application/x-futuresplash" },
	{ "gnumeric", "application/x-gnumeric" },
	{ "sgf", "application/x-go-sgf" },
	{ "gcf", "application/x-graphing-calculator" },
	{ "hdf", "application/x-hdf" },
	{ "phtml", "application/x-httpd-php" },
	{ "pht", "application/x-httpd-php" },
	{ "php", "application/x-httpd-php" },
	{ "phps", "application/x-httpd-php-source" },
	{ "php3", "application/x-httpd-php3" },
	{ "php3p", "application/x-httpd-php3-preprocessed" },
	{ "php4", "application/x-httpd-php4" },
	{ "ica", "application/x-ica" },
	{ "ins", "application/x-internet-signup" },
	{ "isp", "application/x-internet-signup" },
	{ "iii", "application/x-iphone" },
	{ "iso", "application/x-iso9660-image" },
	{ "jam", "application/x-jam" },
	{ "jnlp", "application/x-java-jnlp-file" },
	{ "jmz", "application/x-jmol" },
	{ "chrt", "application/x-kchart" },
	{ "kil", "application/x-killustrator" },
	{ "skp", "application/x-koan" },
	{ "skd", "application/x-koan" },
	{ "skt", "application/x-koan" },
	{ "skm", "application/x-koan" },
	{ "kpr", "application/x-kpresenter" },
	{ "kpt", "application/x-kpresenter" },
	{ "ksp", "application/x-kspread" },
	{ "kwd", "application/x-kword" },
	{ "kwt", "application/x-kword" },
	{ "latex", "application/x-latex" },
	{ "lha", "application/x-lha" },
	{ "lyx", "application/x-lyx" },
	{ "lzh", "application/x-lzh" },
	{ "lzx", "application/x-lzx" },
	{ "frm", "application/x-maker" },
	{ "maker", "application/x-maker" },
	{ "frame", "application/x-maker" },
	{ "fm", "application/x-maker" },
	{ "mif", "application/x-mif" },
	{ "wmd", "application/x-ms-wmd" },
	{ "wmz", "application/x-ms-wmz" },
	{ "com", "application/x-msdos-program" },
	{ "exe", "application/x-msdos-program" },
	{ "bat", "application/x-msdos-program" },
	{ "dll", "application/x-msdos-program" },
	{ "msi", "application/x-msi" },
	{ "nc", "application/x-netcdf" },
	{ "pac", "application/x-ns-proxy-autoconfig" },
	{ "dat", "application/x-ns-proxy-autoconfig" },
	{ "nwc", "application/x-nwc" },
	{ "o", "application/x-object" },
	{ "oza", "application/x-oz-application" },
	{ "p7r", "application/x-pkcs7-certreqresp" },
	{ "crl", "application/x-pkcs7-crl" },
	{ "pyc", "application/x-python-code" },
	{ "pyo", "application/x-python-code" },
	{ "qtl", "application/x-quicktimeplayer" },
	{ "rpm", "application/x-redhat-package-manager" },
	{ "rb", "application/x-ruby" },
	{ "sit", "application/x-stuffit" },
	{ "sitx", "application/x-stuffit" },
	{ "sv4cpio", "application/x-sv4cpio" },
	{ "sv4crc", "application/x-sv4crc" },
	{ "tar", "application/x-tar" },
	{ "tcl", "application/x-tcl" },
	{ "gf", "application/x-tex-gf" },
	{ "pk", "application/x-tex-pk" },
	{ "texinfo", "application/x-texinfo" },
	{ "texi", "application/x-texinfo" },
	{ "~", "application/x-trash" },
	{ "%", "application/x-trash" },
	{ "bak", "application/x-trash" },
	{ "old", "application/x-trash" },
	{ "t", "application/x-troff" },
	{ "tr", "application/x-troff" },
	{ "roff", "application/x-troff" },
	{ "man", "application/x-troff-man" },
	{ "me", "application/x-troff-me" },
	{ "ms", "application/x-troff-ms" },
	{ "ustar", "application/x-ustar" },
	{ "src", "application/x-wais-source" },
	{ "wz", "application/x-wingz" },
	{ "crt", "application/x-x509-ca-cert" },
	{ "xcf", "application/x-xcf" },
	{ "fig", "application/x-xfig" },
	{ "xpi", "application/x-xpinstall" },
	{ "au", "audio/basic" },
	{ "snd", "audio/basic" },
	{ "mid", "audio/midi" },
	{ "midi", "audio/midi" },
	{ "kar", "audio/midi" },
	{ "sid", "audio/prs.sid" },
	{ "aif", "audio/x-aiff" },
	{ "aiff", "audio/x-aiff" },
	{ "aifc", "audio/x-aiff" },
	{ "gsm", "audio/x-gsm" },
	{ "mpga", "audio/mpeg" },
	{ "mpega", "audio/mpeg" },
	{ "wax", "audio/x-ms-wax" },
	{ "ra", "audio/x-pn-realaudio" },
	{ "rm", "audio/x-pn-realaudio" },
	{ "ram", "audio/x-pn-realaudio" },
	{ "ra", "audio/x-realaudio" },
	{ "pls", "audio/x-scpls" },
	{ "sd2", "audio/x-sd2" },
	{ "wav", "audio/x-wav" },
	{ "alc", "chemical/x-alchemy" },
	{ "cac", "chemical/x-cache" },
	{ "cache", "chemical/x-cache" },
	{ "csf", "chemical/x-cache-csf" },
	{ "cbin", "chemical/x-cactvs-binary" },
	{ "cascii", "chemical/x-cactvs-binary" },
	{ "ctab", "chemical/x-cactvs-binary" },
	{ "cdx", "chemical/x-cdx" },
	{ "cer", "chemical/x-cerius" },
	{ "c3d", "chemical/x-chem3d" },
	{ "chm", "chemical/x-chemdraw" },
	{ "cif", "chemical/x-cif" },
	{ "cmdf", "chemical/x-cmdf" },
	{ "cml", "chemical/x-cml" },
	{ "cpa", "chemical/x-compass" },
	{ "bsd", "chemical/x-crossfire" },
	{ "csml", "chemical/x-csml" },
	{ "csm", "chemical/x-csml" },
	{ "ctx", "chemical/x-ctx" },
	{ "cxf", "chemical/x-cxf" },
	{ "cef", "chemical/x-cxf" },
	{ "smi", "#chemical/x-daylight-smiles" },
	{ "emb", "chemical/x-embl-dl-nucleotide" },
	{ "embl", "chemical/x-embl-dl-nucleotide" },
	{ "spc", "chemical/x-galactic-spc" },
	{ "inp", "chemical/x-gamess-input" },
	{ "gam", "chemical/x-gamess-input" },
	{ "gamin", "chemical/x-gamess-input" },
	{ "fch", "chemical/x-gaussian-checkpoint" },
	{ "fchk", "chemical/x-gaussian-checkpoint" },
	{ "cub", "chemical/x-gaussian-cube" },
	{ "gau", "chemical/x-gaussian-input" },
	{ "gjc", "chemical/x-gaussian-input" },
	{ "gjf", "chemical/x-gaussian-input" },
	{ "gal", "chemical/x-gaussian-log" },
	{ "gcg", "chemical/x-gcg8-sequence" },
	{ "gen", "chemical/x-genbank" },
	{ "hin", "chemical/x-hin" },
	{ "istr", "chemical/x-isostar" },
	{ "ist", "chemical/x-isostar" },
	{ "jdx", "chemical/x-jcamp-dx" },
	{ "dx", "chemical/x-jcamp-dx" },
	{ "kin", "chemical/x-kinemage" },
	{ "mcm", "chemical/x-macmolecule" },
	{ "mmd", "chemical/x-macromodel-input" },
	{ "mmod", "chemical/x-macromodel-input" },
	{ "mol", "chemical/x-mdl-molfile" },
	{ "rd", "chemical/x-mdl-rdfile" },
	{ "rxn", "chemical/x-mdl-rxnfile" },
	{ "sd", "chemical/x-mdl-sdfile" },
	{ "sdf", "chemical/x-mdl-sdfile" },
	{ "tgf", "chemical/x-mdl-tgf" },
	{ "mif", "#chemical/x-mif" },
	{ "mcif", "chemical/x-mmcif" },
	{ "mol2", "chemical/x-mol2" },
	{ "b", "chemical/x-molconn-Z" },
	{ "gpt", "chemical/x-mopac-graph" },
	{ "mop", "chemical/x-mopac-input" },
	{ "mopcrt", "chemical/x-mopac-input" },
	{ "mpc", "chemical/x-mopac-input" },
	{ "zmt", "chemical/x-mopac-input" },
	{ "moo", "chemical/x-mopac-out" },
	{ "mvb", "chemical/x-mopac-vib" },
	{ "asn", "chemical/x-ncbi-asn1" },
	{ "prt", "chemical/x-ncbi-asn1-ascii" },
	{ "ent", "chemical/x-ncbi-asn1-ascii" },
	{ "val", "chemical/x-ncbi-asn1-binary" },
	{ "aso", "chemical/x-ncbi-asn1-binary" },
	{ "asn", "chemical/x-ncbi-asn1-spec" },
	{ "pdb", "chemical/x-pdb" },
	{ "ent", "chemical/x-pdb" },
	{ "ros", "chemical/x-rosdal" },
	{ "sw", "chemical/x-swissprot" },
	{ "vms", "chemical/x-vamas-iso14976" },
	{ "vmd", "chemical/x-vmd" },
	{ "xtel", "chemical/x-xtel" },
	{ "xyz", "chemical/x-xyz" },
	{ "ief", "image/ief" },
	{ "jpe", "image/jpeg" },
	{ "pcx", "image/pcx" },
	{ "tif", "image/tiff" },
	{ "djvu", "image/vnd.djvu" },
	{ "djv", "image/vnd.djvu" },
	{ "wbmp", "image/vnd.wap.wbmp" },
	{ "ras", "image/x-cmu-raster" },
	{ "cdr", "image/x-coreldraw" },
	{ "pat", "image/x-coreldrawpattern" },
	{ "cdt", "image/x-coreldrawtemplate" },
	{ "cpt", "image/x-corelphotopaint" },
	{ "ico", "image/x-icon" },
	{ "art", "image/x-jg" },
	{ "jng", "image/x-jng" },
	{ "bmp", "image/x-ms-bmp" },
	{ "psd", "image/x-photoshop" },
	{ "pnm", "image/x-portable-anymap" },
	{ "pbm", "image/x-portable-bitmap" },
	{ "pgm", "image/x-portable-graymap" },
	{ "ppm", "image/x-portable-pixmap" },
	{ "rgb", "image/x-rgb" },
	{ "xbm", "image/x-xbitmap" },
	{ "xpm", "image/x-xpixmap" },
	{ "xwd", "image/x-xwindowdump" },
	{ "eml", "message/rfc822" },
	{ "igs", "model/iges" },
	{ "iges", "model/iges" },
	{ "msh", "model/mesh" },
	{ "mesh", "model/mesh" },
	{ "silo", "model/mesh" },
	{ "wrl", "model/vrml" },
	{ "vrml", "model/vrml" },
	{ "ics", "text/calendar" },
	{ "icz", "text/calendar" },
	{ "csv", "text/csv" },
	{ "323", "text/h323" },
	{ "uls", "text/iuls" },
	{ "mml", "text/mathml" },
	{ "pot", "text/plain" },
	{ "rtx", "text/richtext" },
	{ "sct", "text/scriptlet" },
	{ "wsc", "text/scriptlet" },
	{ "tm", "text/texmacs" },
	{ "ts", "text/texmacs" },
	{ "tsv", "text/tab-separated-values" },
	{ "jad", "text/vnd.sun.j2me.app-descriptor" },
	{ "wml", "text/vnd.wap.wml" },
	{ "wmls", "text/vnd.wap.wmlscript" },
	{ "bib", "text/x-bibtex" },
	{ "boo", "text/x-boo" },
	{ "h++", "text/x-c++hdr" },
	{ "hpp", "text/x-c++hdr" },
	{ "hxx", "text/x-c++hdr" },
	{ "hh", "text/x-c++hdr" },
	{ "c++", "text/x-c++src" },
	{ "cpp", "text/x-c++src" },
	{ "cxx", "text/x-c++src" },
	{ "cc", "text/x-c++src" },
	{ "h", "text/x-chdr" },
	{ "htc", "text/x-component" },
	{ "csh", "text/x-csh" },
	{ "c", "text/x-csrc" },
	{ "d", "text/x-dsrc" },
	{ "diff", "text/x-diff" },
	{ "patch", "text/x-diff" },
	{ "hs", "text/x-haskell" },
	{ "java", "text/x-java" },
	{ "lhs", "text/x-literate-haskell" },
	{ "moc", "text/x-moc" },
	{ "p", "text/x-pascal" },
	{ "pas", "text/x-pascal" },
	{ "gcd", "text/x-pcs-gcd" },
	{ "pl", "text/x-perl" },
	{ "pm", "text/x-perl" },
	{ "py", "text/x-python" },
	{ "etx", "text/x-setext" },
	{ "sh", "text/x-sh" },
	{ "tcl", "text/x-tcl" },
	{ "tk", "text/x-tcl" },
	{ "tex", "text/x-tex" },
	{ "ltx", "text/x-tex" },
	{ "sty", "text/x-tex" },
	{ "cls", "text/x-tex" },
	{ "vcs", "text/x-vcalendar" },
	{ "vcf", "text/x-vcard" },
	{ "3gp", "video/3gpp" },
	{ "dl", "video/dl" },
	{ "dif", "video/dv" },
	{ "dv", "video/dv" },
	{ "fli", "video/fli" },
	{ "gl", "video/gl" },
	{ "mxu", "video/vnd.mpegurl" },
	{ "flv", "video/x-flv" },
	{ "lsf", "video/x-la-asf" },
	{ "lsx", "video/x-la-asf" },
	{ "mng", "video/x-mng" },
	{ "asx", "video/x-ms-asf" },
	{ "wm", "video/x-ms-wm" },
	{ "wmx", "video/x-ms-wmx" },
	{ "wvx", "video/x-ms-wvx" },
	{ "avi", "video/x-msvideo" },
	{ "movie", "video/x-sgi-movie" },
	{ "ice", "x-conference/x-cooltalk" },
	{ "sisx", "x-epoc/x-sisx-app" },
	{ "vrm", "x-world/x-vrml" },
	{ "vrml", "x-world/x-vrml" },
	{ "wrl", "x-world/x-vrml" },
	{ NULL, NULL}
};


