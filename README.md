# buttermilk tweetnacl-java

This was forked from https://github.com/ianopolous/tweetnacl-java/

* Mavenized
* Formatted the code to please my eyes  
* Transformed most of the static methods into instance methods

It is a little frustrating that the code translators took a C program in the public domain and GPL'd their
resulting translation into java. Kudo's to them, but the license is less than helpful since the original C code
is explicitly intended to be included directly in projects! Not just GPL projects! 

Well, that's what was done. So I can't include this in buttermilk-core as a result, I have an Apache license 
over there or in some cases a FOSS exception to GPL, but not GPLv2 as such.

However we can still do some things with the code. In keeping with the idea of being concise we can format the keys
and do some other integrations in a concise way.  
