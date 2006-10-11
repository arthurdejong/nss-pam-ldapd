#!/usr/bin/perl

#
# $Header: /home/project/cvs/nss_ldap/tests/ldaptest.pl,v 1.2 2001/01/09 00:21:21 lukeh Exp $
#


sub printarr {
  foreach (@_) {
    print $_." ";
  }
  print "\n";
}
sub printhost {
  foreach (@_) {
    if ($_ !~ /^[\w\.\d]+$/) {
      @addr = unpack('C4',$_);
      print $addr[0].".".$addr[1].".".$addr[2].".".$addr[3]." ";
    } else {
      print $_." ";
    }
  }
  print "\n";
}


print "*** getpwnam ***\n";
printarr(getpwnam("root"));
print "*** getpwuid ***\n";
printarr(getpwuid(0));
print "*** setpwent ***\n";
setpwent();
print "*** getpwent ***\n";
while(@ent = getpwent()) {
  printarr(@ent);
}
print "*** endpwent ***\n";
endpwent();
print "*** getgrnam ***\n";
printarr(getgrnam("wheel"));
print "*** getgrgid ***\n";
printarr(getgrgid(10));
print "*** setgrent ***\n";
setgrent();
print "*** getgrent ***\n";
while(@ent = getgrent()) {
  printarr(@ent);
}
print "*** endgrent ***\n";
endgrent();
print "*** gethostbyname ***\n";
printhost(gethostbyname("localhost"));
print "*** gethostbyaddr ***\n";
printhost(gethostbyaddr(pack(C4,(127,0,0,1)),2));
print "*** sethostent ***\n";
sethostent(0);
print "*** gethostent ***\n";
while(@ent = gethostent()) {
  printhost(@ent);
}
print "*** endhostent ***\n";
endhostent();
# I dont appear to have networks. but we'll try anyway.
print "*** getnetbyname ***\n";
printhost(getnetbyname("localnet"));
print "*** getnetbyaddr ***\n";
# this may not be the right call. who uses 'networks' anyways!?
printhost(getnetbyaddr(127,2));
print "*** setnetent ***\n";
setnetent(0);
print "*** getnetent ***\n";
while(@ent = getnetent()) {
  printhost(@ent);
}
print "*** endnetent ***\n";
endnetent();
print "*** getservbyname ***\n";
printarr(getservbyname("telnet","tcp"));
print "*** getservbyport ***\n";
printarr(getservbyport(23,"tcp"));
print "*** setservent ***\n";
setservent(0);
print "*** getservent ***\n";
while(@ent = getservent()) {
  printarr(@ent);
}
print "*** endservent ***\n";
endservent();
print "*** getprotobyname ***\n";
printarr(getprotobyname("icmp"));
print "*** getprotobynumber ***\n";
printarr(getprotobynumber(1));
print "*** setprotoent ***\n";
setprotoent(0);
print "*** getprotoent ***\n";
while(@ent = getprotoent()) {
  printarr(@ent);
}
print "*** endprotoent ***\n";
endprotoent();

