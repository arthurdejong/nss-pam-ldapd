#!/bin/sh

# test_nsscmds.sh - simple test script to check output of name lookup commands
#
# Copyright (C) 2007, 2008, 2009, 2010, 2011, 2013 Arthur de Jong
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA

# This script expects to be run in an environment where nss-pam-ldapd
# is deployed with an LDAP server with the proper content (and nslcd running).
# It's probably best to run this in an environment without nscd (this breaks
# the services tests).

set -e

# find source directory
srcdir="${srcdir-`dirname "$0"`}"

# ensure that we are running in the test environment
. "$srcdir/in_testenv.sh"

# preload our own NSS module
LD_PRELOAD="$srcdir/../nss/nss_ldap.so"
export LD_PRELOAD

# the total number of errors
FAIL=0

check() {
  # the command to execute
  cmd="$1"
  # save the expected output
  expectfile=`mktemp -t expected.XXXXXX 2> /dev/null || tempfile -s .expected 2> /dev/null`
  cat > "$expectfile"
  # run the command
  echo 'test_nsscmds.sh: checking "'"$cmd"'"'
  actualfile=`mktemp -t actual.XXXXXX 2> /dev/null || tempfile -s .actual 2> /dev/null`
  eval "$cmd" > "$actualfile" 2>&1 || true
  # check for differences
  diff -Nauwi "$expectfile" "$actualfile" || FAIL=`expr $FAIL + 1`
  # remove temporary files
  rm "$expectfile" "$actualfile"
}

###########################################################################

if grep '^aliases.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing aliases..."

# note that this doesn't work if /etc/aliases contains anything

# check all aliases
check "getent aliases|sort" << EOM
bar2:           foobar@example.com
bar:            foobar@example.com
foo:            bar@example.com
EOM

# get alias by name
check "getent aliases foo" << EOM
foo:            bar@example.com
EOM

# get alias by second name
check "getent aliases bar2" << EOM
bar2:           foobar@example.com
EOM

# get alias by different case
check "getent aliases FOO" << EOM
foo:            bar@example.com
EOM

fi  # end of aliases tests

###########################################################################

if grep '^ethers.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing ether..."

# get an entry by hostname
check "getent ethers testhost" << EOM
0:18:8a:54:1a:8e testhost
EOM

# get an entry by alias name
check "getent ethers testhostalias" << EOM
0:18:8a:54:1a:8e testhostalias
EOM

# get an entry by hostname with different case
check "getent ethers TESTHOST" << EOM
0:18:8a:54:1a:8e testhost
EOM

# get an entry by ethernet address
check "getent ethers 0:18:8a:54:1a:8b" << EOM
0:18:8a:54:1a:8b testhost2
EOM

# get entry by ip address
# this does not currently work, but maybe it should
#check "getent ethers 10.0.0.1" << EOM
#0:18:8a:54:1a:8e testhost
#EOM

# get all ethers (unsupported)
check "getent ethers" << EOM
Enumeration not supported on ethers
EOM

fi  # end of ethers tests

###########################################################################

if grep '^group.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing group..."

# function to sort group members of a group
sortgroup() {
  while read line
  do
    group="$(echo "$line" | sed 's/^\(.*:.*:.*:\).*/\1/')"
    members="$(echo "$line" | sed 's/^.*:.*:.*://' | tr ',' '\n' | sort | tr '\n' ',' | sed 's/,$//')"
    echo "${group}${members}"
  done
}

check "getent group testgroup | sortgroup" << EOM
testgroup:*:6100:arthur,test,testuser4
EOM

# this does not work because users is in /etc/group but it would
# be nice if libc supported this
#check "getent group users" << EOM
#users:*:100:arthur,test
#EOM

# group with different case should not be found
check "getent group TESTGROUP" << EOM
EOM

check "getent group 6100 | sortgroup" << EOM
testgroup:*:6100:arthur,test,testuser4
EOM

check "groups arthur | sed 's/^.*://'" << EOM
users testgroup testgroup2 grp4 grp5 grp6 grp7 grp8 grp9 grp10 grp11 grp12 grp13 grp14 grp15 grp16 grp17 grp18
EOM

check "groups testuser4 | sed 's/^.*://'" << EOM
users testgroup testgroup2
EOM

check "getent group | egrep '^(testgroup|users):' | sortgroup" << EOM
users:x:100:
testgroup:*:6100:arthur,test,testuser4
users:*:100:arthur,test
EOM

check "getent group | wc -l" << EOM
`grep -c : /etc/group | awk '{print $1 + 20}'`
EOM

check "getent group | grep ^largegroup | sortgroup" << EOM
largegroup:*:1005:akraskouskas,alat,ameisinger,bdevera,behrke,bmoldan,btempel,cjody,clouder,cmanno,dbye,dciviello,dfirpo,dgivliani,dgosser,emcquiddy,enastasi,fcunard,gcubbison,gdaub,gdreitzler,ghanauer,gpomerance,gsusoev,gtinnel,gvollrath,gzuhlke,hgalavis,hhaffey,hhydrick,hmachesky,hpaek,hpolk,hsweezer,htomlinson,hzagami,igurwell,ihashbarger,jyeater,kbradbury,khathway,kklavetter,lbuchtel,lgandee,lkhubba,lmauracher,lseehafer,lvittum,mblanchet,mbodley,mciaccia,mjuris,ndipanfilo,nfilipek,nfunchess,ngata,ngullett,nkraker,nriofrio,nroepke,nrybij,oclunes,oebrani,okveton,osaines,otrevor,pdossous,phaye,psowa,purquilla,rkoonz,rlatessa,rworkowski,sdebry,sgurski,showe,slaforge,tabdelal,testusr2,testusr3,tfalconeri,tpaa,uschweyen,utrezize,vchevalier,vdelnegro,vleyton,vmedici,vmigliori,vpender,vwaltmann,wbrettschneide,wselim,wvalcin,wworf,yautin,ykisak,zgingrich,znightingale,zwinterbottom
EOM

check "getent group largegroup | sortgroup" << EOM
largegroup:*:1005:akraskouskas,alat,ameisinger,bdevera,behrke,bmoldan,btempel,cjody,clouder,cmanno,dbye,dciviello,dfirpo,dgivliani,dgosser,emcquiddy,enastasi,fcunard,gcubbison,gdaub,gdreitzler,ghanauer,gpomerance,gsusoev,gtinnel,gvollrath,gzuhlke,hgalavis,hhaffey,hhydrick,hmachesky,hpaek,hpolk,hsweezer,htomlinson,hzagami,igurwell,ihashbarger,jyeater,kbradbury,khathway,kklavetter,lbuchtel,lgandee,lkhubba,lmauracher,lseehafer,lvittum,mblanchet,mbodley,mciaccia,mjuris,ndipanfilo,nfilipek,nfunchess,ngata,ngullett,nkraker,nriofrio,nroepke,nrybij,oclunes,oebrani,okveton,osaines,otrevor,pdossous,phaye,psowa,purquilla,rkoonz,rlatessa,rworkowski,sdebry,sgurski,showe,slaforge,tabdelal,testusr2,testusr3,tfalconeri,tpaa,uschweyen,utrezize,vchevalier,vdelnegro,vleyton,vmedici,vmigliori,vpender,vwaltmann,wbrettschneide,wselim,wvalcin,wworf,yautin,ykisak,zgingrich,znightingale,zwinterbottom
EOM

check "getent group | grep ^hugegroup | sortgroup" << EOM
hugegroup:*:1006:ablackstock,abortignon,achhor,ademosthenes,adenicola,adishaw,aesbensen,aferge,afredin,afuchs,agarbett,agimm,agordner,ahandy,ajaquess,akertzman,akomsthoeft,akraskouskas,akravetz,alamour,alat,alienhard,amanganelli,amaslyn,amayorga,amccroskey,amcgraw,amckinney,ameisinger,aponcedeleon,apurdon,areid,arosel,ascheno,ascovel,asemons,ashuey,asivley,astrunk,atollefsrud,atonkin,awhitt,aziernicki,badair,baigner,bbeckfield,bbrenton,bcoletta,bcolorado,bdadds,bdaughenbaugh,bdevera,bdominga,behrke,beon,bfishbeck,bgavagan,bguthary,bharnois,bhelverson,bjolly,blovig,bluellen,bmadamba,bmarlin,bmarszalek,bmicklos,bmoling,bouten,bphou,bpinedo,brodgerson,broher,bromano,bscadden,bsibal,bstrede,bswantak,btempel,btheim,bveeneman,bwinterton,bwynes,cabare,carguellez,cbarlup,cbartnick,cbelardo,cbleimehl,cbotdorf,cbourek,cbrechbill,cbrom,ccyganiewicz,cdeckard,cdegravelle,cdickes,cdrumm,cfasone,cflenner,cfleurantin,cgaler,cgalinol,cgaudette,cghianni,charriman,cjody,cjuntunen,ckerska,ckistenmacher,cklem,ckodish,clapenta,clewicki,clouder,cmafnas,cmanno,cmcanulty,cmellberg,cmiramon,cnabzdyk,cnoriego,cpaccione,cpalmios,cparee,cpencil,cpentreath,cpinela,cpluid,critchie,cscullion,csever,csoomaroo,cspilis,cswigert,ctenny,ctetteh,ctuzzo,cwank,cweiss,dasiedu,daubert,dbarriball,dbertels,dblazejewski,dcaltabiano,dciullo,ddeguire,ddigerolamo,denriquez,deshmon,dfirpo,dflore,dfollman,dgiacomazzi,dgivliani,dgosser,dhammontree,dhendon,dhindsman,dholdaway,dlablue,dlanois,dlargo,dledenbach,dlongbotham,dloubier,dmahapatra,dmarchizano,dmcgillen,dminozzi,dnegri,dpebbles,draymundo,dscheurer,dsharr,dsherard,dsteever,dtashjian,dtornow,dtuholski,dwittlinger,dzurek,eaguire,eathey,ebattee,ebeachem,eberkman,ebusk,ecelestin,ecolden,ecordas,ediga,edrinkwater,edurick,egospatrick,egrago,ehathcock,ehindbaugh,ejeppesen,ekalfas,ekenady,ekeuper,eklein,eklunder,ekurter,emanikowski,emargulis,emcquiddy,emehta,eorsten,eparham,epeterson,epoinelli,erathert,erostad,eserrett,esheehan,esonia,esproull,esthill,estockwin,etunby,ewicks,ewilles,ewismer,ewuitschick,eyounglas,eziebert,fagro,faleo,farquette,fbeatrice,fberra,fberyman,fbielecki,fburrough,fcha,fcunard,ffigert,fgoben,fgrashot,fhain,fhalon,fkeef,fmarchi,fmilsaps,fnottage,fparness,fplayfair,fsapien,fsavela,fsirianni,fsplinter,fsunderland,fsymmonds,fthein,fvallian,fvascones,fverfaille,fvinal,fwidhalm,gallanson,gapkin,garchambeault,gbitar,gbolay,gcarlini,gcervantez,gchounlapane,gclapham,gcobane,gconver,gcukaj,gcummer,gcurnutt,gdaub,gdeblasio,gdeyarmond,gdrilling,gearnshaw,gfaire,gfedewa,ggehrke,ggillim,ghann,ghelderman,ghumbles,gishii,gjankowiak,gkerens,glafontaine,gloebs,gmackinder,gmassi,gmilian,gmings,gmoen,gparkersmith,gpomerance,gportolese,greiff,gsantella,gschaumburg,gshrode,gtinnel,guresti,gvollrath,gwaud,habby,hbastidos,hbetterman,hbickford,hbraim,hbrandow,hbrehmer,hbukovsky,hcafourek,hcarrizal,hchaviano,hcintron,hcowles,hcusta,hdoiel,hdyner,hfludd,hgalavis,hhaffey,hhagee,hhartranft,hholyfield,hhysong,hkarney,hkinderknecht,hkippes,hkohlmeyer,hlauchaire,hlemon,hlichota,hliverman,hloftis,hlynema,hmateer,hmatonak,hmiazga,hmogush,hmuscaro,hpalmquist,hpimpare,hpolintan,hrapisura,hrenart,hriech,hsabol,hschelb,hschoepfer,hspiry,hstreitnatter,hsweezer,htilzer,htomlinson,htsuha,hvannette,hveader,hwestermark,hwoodert,hzagami,hzinda,iambrosino,ibeto,ibreitbart,ibuzo,ibyles,ichewning,icoard,ideveyra,ienglert,igizzi,ihalford,ihanneman,ihegener,ihernan,iherrarte,ihimmelwright,ihoa,iiffert,ikadar,ikulbida,ilacourse,ilamberth,ilawbaugh,ileaman,ilevian,imarungo,imcbay,imensah,imicthell,imillin,imuehl,inarain,iogasawara,iroiger,iseipel,isowder,isplonskowski,istallcup,istarring,isteinlicht,ithum,ivanschaack,iweibe,iyorgey,iyorks,jamber,jappleyard,jbielicki,jbjorkman,jcaroll,jdodge,jeuresti,jeverton,jglotzbecker,jherkenratt,jholzmiller,jjumalon,jkimpton,jknight,jlebouf,jlunney,jmartha,jmarugg,jmatty,joligee,jquicksall,jrees,jreigh,jroman,jscheitlin,jseen,jsegundo,jsenavanh,jskafec,jspohn,jsweezy,jvillaire,jwinterton,jzych,kaanerud,kalguire,kbarnthouse,kbartolet,kbattershell,kbrevitz,kbrugal,kcofrancesco,kcomparoni,kconkey,kdevincent,kepps,kfaure,kfend,kgarced,kgremminger,khartness,kheadlon,khovanesian,kjoslyn,klitehiser,klundsten,klurie,kmallach,kmandolfo,kmarzili,kmayoras,kmcardle,kmcguire,kmedcaf,kmeester,kmisove,kmoesch,kmosko,kmuros,kolexa,kottomaniello,kpalka,kpannunzio,kpenale,kpuebla,krahman,kseisler,kshippy,ksiering,ksollitto,ksparling,kstachurski,kthede,ktoni,ktriblett,ktuccio,ktuner,kwidrick,kwinterling,kwirght,laksamit,lautovino,lbanco,lbassin,lbove,lbuchtel,lcanestrini,lcaudell,lcavez,lcocherell,lcoulon,lcremer,leberhardt,lfarraj,lfichtner,lgadomski,lgandee,lgradilla,lhuggler,limbrogno,ljomes,lkimel,llarmore,llasher,lmadruga,lmauracher,lmcgeary,lmichaud,lmuehlberger,lnormand,lparrish,lpeagler,lpintor,lpitek,lpondexter,lrandall,lringuette,lschenkelberg,lschnorbus,lschollmeier,lseabold,lseehafer,lshilling,lsivic,lsobrino,lsous,lspielvogel,lvaleriano,lvanconant,lwedner,lyoula,mallmand,maustine,mbeagley,mbodley,mbravata,mcampagnone,mcaram,mcashett,mcasida,mcoch,mcolehour,mcontreras,mdanos,mdecourcey,mdedon,mdickinson,mdimaio,mdoering,mdyce,meconomides,mespinel,mfaeth,mfeil,mferandez,mfitzherbert,mgavet,mgayden,mground,mheilbrun,mhollings,mjeon,mkibler,mkofoed,mlaverde,mlenning,mlinak,mlinardi,mmangiamele,mmattu,mmcchristian,mmerriwether,mmesidor,mneubacher,moller,moser,mpanahon,mpark,mpellew,mpilon,mpizzaro,mpytko,mquigg,mredd,mrizer,mruppel,mrydelek,mskeele,mstirn,mswogger,mtanzi,mtintle,mvanbergen,mvanpelt,mvas,mvedder,mviverette,myokoyama,nagerton,nasmar,nbuford,nbugtong,ncermeno,nchrisman,nciucci,ndesautels,ndrumgole,nedgin,nendicott,nerbach,nevan,nforti,nfunchess,ngiesler,nglathar,ngrowney,ngullett,nhayer,nhelfinstine,nhija,ninnella,njordon,nkempon,nkubley,nlainhart,nlatchaw,nlemma,nlinarez,nlohmiller,nmccolm,nmoren,nnamanworth,nnickel,nousdahl,nphan,nramones,nranck,nridinger,nriofrio,nrybij,nrysavy,nschmig,nsiemonsma,nslaby,nspolar,nvyhnal,nwescott,nwiker,oahyou,oalthouse,obeaufait,obenallack,obercier,obihl,ocalleo,ochasten,oclunes,oconerly,ocrabbs,oebrani,ofelcher,ohatto,ohearl,ohedlund,ohoffert,ohove,ojerabek,okave,okveton,omalvaez,omasone,omatula,omcdaid,oolivarez,oosterhouse,opeet,opizzuti,opoch,oport,opuglisi,oreiss,osaber,oscarpello,oshough,ovibbert,owhelchel,owhitelow,pahles,pbascom,pbeckerdite,pbiggart,pbondroff,pbrentano,pcaposole,pcornn,pdauterman,pdech,pdischinger,pduitscher,pdulac,pdurando,pfavolise,pgiegerich,pgreenier,pgrybel,phalkett,pheathcock,phyer,pmineo,pminnis,ppedraja,ppeper,pphuaphes,prepasky,prowena,psabado,psalesky,pschrayter,psharits,psiroky,psundeen,pthornberry,ptoenjes,ptraweek,purquilla,pvierthaler,pvirelli,pviviani,pwademan,pwashuk,pwetherwax,pwhitmire,pwohlenhaus,pwutzke,qhanly,ralspach,rbernhagen,rbillingsly,rbloomstrand,rbrisby,rcheshier,rchevrette,rdubs,rdubuisson,redling,rfassinger,rfauerbach,rfidel,rginer,rgoonez,rgramby,rgriffies,rguinane,rheinzmann,rkraszewski,rlambertus,rlatessa,rlosinger,rmandril,rmcstay,rnordby,rpastorin,rpikes,rpinilla,rpitter,rramirez,rrasual,rschkade,rtole,rtooker,saben,sackles,sarndt,saycock,sbemo,sbettridge,sbloise,sbonnie,sbrabyn,scocuzza,sdebry,senrico,sestergard,sgefroh,sgirsh,sgropper,sgunder,sgurski,shaith,sherzberg,showe,sjankauskas,skanjirathinga,skoegler,slaningham,slaudeman,slerew,smccaie,smillian,smullowney,snotari,spolmer,srees,srubenfield,sscheiern,sskone,sskyers,sspagnuolo,sstough,sstuemke,svandewalle,svielle,svogler,svongal,swoodie,tabdelal,tairth,tbagne,tbattista,tboxx,tcacal,tcossa,tcrissinger,tdonathan,teliades,tfalconeri,tfetherston,tgelen,tgindhart,tguinnip,tharr,thelfritz,thoch,thynson,tkeala,tkelly,tkhora,tlana,tlowers,tmalecki,tmarkus,tmccaffity,tmccamish,tmcmickle,tmelland,tmorr,tmurata,tmysinger,tnaillon,tnitzel,tpaa,tplatko,tredfearn,tsablea,tsann,tschnepel,tsearle,tsepulueda,tsowells,tstalworth,tvehrs,tvrooman,tyounglas,ualway,uazatyan,ubenken,ubieniek,ubynum,udatu,uednilao,ueriks,uflander,ugerpheide,ugreenberg,uhayakawa,uholecek,ulanigan,umarbury,umosser,upater,upellam,uransford,urosentrance,uschweyen,usevera,uslavinski,uspittler,uvanmatre,uwalpole,uweyand,vbaldasaro,vbigalow,vbonder,vburton,vchevalier,vcrofton,vdesir,vdolan,veisenhardt,vemily,venfort,vfeigel,vglidden,vkrug,vlubic,vmaynard,vmedici,vnazzal,vnery,vpeairs,vpender,vpiraino,vrodick,vrunyon,vsefcovic,vstirman,vtowell,vtresch,vtrumpp,vwabasha,vwaltmann,vwisinger,vwokwicz,wbrill,wclokecloak,wconces,wconstantino,wcreggett,wdagrella,wdevenish,wdovey,wenglander,werrick,wesguerra,wganther,wkhazaleh,wleiva,wlynch,wmailey,wmendell,wnunziata,wottesen,wselim,wstjean,wtruman,wvalcin,wvermeulen,xeppley,xlantey,xrahaim,yautin,ycerasoli,ycobetto,ycostaneda,yduft,yeven,yfrymoyer,ygockel,yhenriques,ykimbel,yolivier,yschmuff,ysnock,yvdberg,zanderlik,zborgmeyer,zbuscaglia,zculp,zfarler,zhaulk,zkutchera,zmeeker,zneeb,zratti,zscammahorn,zvagt,zwinterbottom
EOM

check "getent group hugegroup | sortgroup" << EOM
hugegroup:*:1006:ablackstock,abortignon,achhor,ademosthenes,adenicola,adishaw,aesbensen,aferge,afredin,afuchs,agarbett,agimm,agordner,ahandy,ajaquess,akertzman,akomsthoeft,akraskouskas,akravetz,alamour,alat,alienhard,amanganelli,amaslyn,amayorga,amccroskey,amcgraw,amckinney,ameisinger,aponcedeleon,apurdon,areid,arosel,ascheno,ascovel,asemons,ashuey,asivley,astrunk,atollefsrud,atonkin,awhitt,aziernicki,badair,baigner,bbeckfield,bbrenton,bcoletta,bcolorado,bdadds,bdaughenbaugh,bdevera,bdominga,behrke,beon,bfishbeck,bgavagan,bguthary,bharnois,bhelverson,bjolly,blovig,bluellen,bmadamba,bmarlin,bmarszalek,bmicklos,bmoling,bouten,bphou,bpinedo,brodgerson,broher,bromano,bscadden,bsibal,bstrede,bswantak,btempel,btheim,bveeneman,bwinterton,bwynes,cabare,carguellez,cbarlup,cbartnick,cbelardo,cbleimehl,cbotdorf,cbourek,cbrechbill,cbrom,ccyganiewicz,cdeckard,cdegravelle,cdickes,cdrumm,cfasone,cflenner,cfleurantin,cgaler,cgalinol,cgaudette,cghianni,charriman,cjody,cjuntunen,ckerska,ckistenmacher,cklem,ckodish,clapenta,clewicki,clouder,cmafnas,cmanno,cmcanulty,cmellberg,cmiramon,cnabzdyk,cnoriego,cpaccione,cpalmios,cparee,cpencil,cpentreath,cpinela,cpluid,critchie,cscullion,csever,csoomaroo,cspilis,cswigert,ctenny,ctetteh,ctuzzo,cwank,cweiss,dasiedu,daubert,dbarriball,dbertels,dblazejewski,dcaltabiano,dciullo,ddeguire,ddigerolamo,denriquez,deshmon,dfirpo,dflore,dfollman,dgiacomazzi,dgivliani,dgosser,dhammontree,dhendon,dhindsman,dholdaway,dlablue,dlanois,dlargo,dledenbach,dlongbotham,dloubier,dmahapatra,dmarchizano,dmcgillen,dminozzi,dnegri,dpebbles,draymundo,dscheurer,dsharr,dsherard,dsteever,dtashjian,dtornow,dtuholski,dwittlinger,dzurek,eaguire,eathey,ebattee,ebeachem,eberkman,ebusk,ecelestin,ecolden,ecordas,ediga,edrinkwater,edurick,egospatrick,egrago,ehathcock,ehindbaugh,ejeppesen,ekalfas,ekenady,ekeuper,eklein,eklunder,ekurter,emanikowski,emargulis,emcquiddy,emehta,eorsten,eparham,epeterson,epoinelli,erathert,erostad,eserrett,esheehan,esonia,esproull,esthill,estockwin,etunby,ewicks,ewilles,ewismer,ewuitschick,eyounglas,eziebert,fagro,faleo,farquette,fbeatrice,fberra,fberyman,fbielecki,fburrough,fcha,fcunard,ffigert,fgoben,fgrashot,fhain,fhalon,fkeef,fmarchi,fmilsaps,fnottage,fparness,fplayfair,fsapien,fsavela,fsirianni,fsplinter,fsunderland,fsymmonds,fthein,fvallian,fvascones,fverfaille,fvinal,fwidhalm,gallanson,gapkin,garchambeault,gbitar,gbolay,gcarlini,gcervantez,gchounlapane,gclapham,gcobane,gconver,gcukaj,gcummer,gcurnutt,gdaub,gdeblasio,gdeyarmond,gdrilling,gearnshaw,gfaire,gfedewa,ggehrke,ggillim,ghann,ghelderman,ghumbles,gishii,gjankowiak,gkerens,glafontaine,gloebs,gmackinder,gmassi,gmilian,gmings,gmoen,gparkersmith,gpomerance,gportolese,greiff,gsantella,gschaumburg,gshrode,gtinnel,guresti,gvollrath,gwaud,habby,hbastidos,hbetterman,hbickford,hbraim,hbrandow,hbrehmer,hbukovsky,hcafourek,hcarrizal,hchaviano,hcintron,hcowles,hcusta,hdoiel,hdyner,hfludd,hgalavis,hhaffey,hhagee,hhartranft,hholyfield,hhysong,hkarney,hkinderknecht,hkippes,hkohlmeyer,hlauchaire,hlemon,hlichota,hliverman,hloftis,hlynema,hmateer,hmatonak,hmiazga,hmogush,hmuscaro,hpalmquist,hpimpare,hpolintan,hrapisura,hrenart,hriech,hsabol,hschelb,hschoepfer,hspiry,hstreitnatter,hsweezer,htilzer,htomlinson,htsuha,hvannette,hveader,hwestermark,hwoodert,hzagami,hzinda,iambrosino,ibeto,ibreitbart,ibuzo,ibyles,ichewning,icoard,ideveyra,ienglert,igizzi,ihalford,ihanneman,ihegener,ihernan,iherrarte,ihimmelwright,ihoa,iiffert,ikadar,ikulbida,ilacourse,ilamberth,ilawbaugh,ileaman,ilevian,imarungo,imcbay,imensah,imicthell,imillin,imuehl,inarain,iogasawara,iroiger,iseipel,isowder,isplonskowski,istallcup,istarring,isteinlicht,ithum,ivanschaack,iweibe,iyorgey,iyorks,jamber,jappleyard,jbielicki,jbjorkman,jcaroll,jdodge,jeuresti,jeverton,jglotzbecker,jherkenratt,jholzmiller,jjumalon,jkimpton,jknight,jlebouf,jlunney,jmartha,jmarugg,jmatty,joligee,jquicksall,jrees,jreigh,jroman,jscheitlin,jseen,jsegundo,jsenavanh,jskafec,jspohn,jsweezy,jvillaire,jwinterton,jzych,kaanerud,kalguire,kbarnthouse,kbartolet,kbattershell,kbrevitz,kbrugal,kcofrancesco,kcomparoni,kconkey,kdevincent,kepps,kfaure,kfend,kgarced,kgremminger,khartness,kheadlon,khovanesian,kjoslyn,klitehiser,klundsten,klurie,kmallach,kmandolfo,kmarzili,kmayoras,kmcardle,kmcguire,kmedcaf,kmeester,kmisove,kmoesch,kmosko,kmuros,kolexa,kottomaniello,kpalka,kpannunzio,kpenale,kpuebla,krahman,kseisler,kshippy,ksiering,ksollitto,ksparling,kstachurski,kthede,ktoni,ktriblett,ktuccio,ktuner,kwidrick,kwinterling,kwirght,laksamit,lautovino,lbanco,lbassin,lbove,lbuchtel,lcanestrini,lcaudell,lcavez,lcocherell,lcoulon,lcremer,leberhardt,lfarraj,lfichtner,lgadomski,lgandee,lgradilla,lhuggler,limbrogno,ljomes,lkimel,llarmore,llasher,lmadruga,lmauracher,lmcgeary,lmichaud,lmuehlberger,lnormand,lparrish,lpeagler,lpintor,lpitek,lpondexter,lrandall,lringuette,lschenkelberg,lschnorbus,lschollmeier,lseabold,lseehafer,lshilling,lsivic,lsobrino,lsous,lspielvogel,lvaleriano,lvanconant,lwedner,lyoula,mallmand,maustine,mbeagley,mbodley,mbravata,mcampagnone,mcaram,mcashett,mcasida,mcoch,mcolehour,mcontreras,mdanos,mdecourcey,mdedon,mdickinson,mdimaio,mdoering,mdyce,meconomides,mespinel,mfaeth,mfeil,mferandez,mfitzherbert,mgavet,mgayden,mground,mheilbrun,mhollings,mjeon,mkibler,mkofoed,mlaverde,mlenning,mlinak,mlinardi,mmangiamele,mmattu,mmcchristian,mmerriwether,mmesidor,mneubacher,moller,moser,mpanahon,mpark,mpellew,mpilon,mpizzaro,mpytko,mquigg,mredd,mrizer,mruppel,mrydelek,mskeele,mstirn,mswogger,mtanzi,mtintle,mvanbergen,mvanpelt,mvas,mvedder,mviverette,myokoyama,nagerton,nasmar,nbuford,nbugtong,ncermeno,nchrisman,nciucci,ndesautels,ndrumgole,nedgin,nendicott,nerbach,nevan,nforti,nfunchess,ngiesler,nglathar,ngrowney,ngullett,nhayer,nhelfinstine,nhija,ninnella,njordon,nkempon,nkubley,nlainhart,nlatchaw,nlemma,nlinarez,nlohmiller,nmccolm,nmoren,nnamanworth,nnickel,nousdahl,nphan,nramones,nranck,nridinger,nriofrio,nrybij,nrysavy,nschmig,nsiemonsma,nslaby,nspolar,nvyhnal,nwescott,nwiker,oahyou,oalthouse,obeaufait,obenallack,obercier,obihl,ocalleo,ochasten,oclunes,oconerly,ocrabbs,oebrani,ofelcher,ohatto,ohearl,ohedlund,ohoffert,ohove,ojerabek,okave,okveton,omalvaez,omasone,omatula,omcdaid,oolivarez,oosterhouse,opeet,opizzuti,opoch,oport,opuglisi,oreiss,osaber,oscarpello,oshough,ovibbert,owhelchel,owhitelow,pahles,pbascom,pbeckerdite,pbiggart,pbondroff,pbrentano,pcaposole,pcornn,pdauterman,pdech,pdischinger,pduitscher,pdulac,pdurando,pfavolise,pgiegerich,pgreenier,pgrybel,phalkett,pheathcock,phyer,pmineo,pminnis,ppedraja,ppeper,pphuaphes,prepasky,prowena,psabado,psalesky,pschrayter,psharits,psiroky,psundeen,pthornberry,ptoenjes,ptraweek,purquilla,pvierthaler,pvirelli,pviviani,pwademan,pwashuk,pwetherwax,pwhitmire,pwohlenhaus,pwutzke,qhanly,ralspach,rbernhagen,rbillingsly,rbloomstrand,rbrisby,rcheshier,rchevrette,rdubs,rdubuisson,redling,rfassinger,rfauerbach,rfidel,rginer,rgoonez,rgramby,rgriffies,rguinane,rheinzmann,rkraszewski,rlambertus,rlatessa,rlosinger,rmandril,rmcstay,rnordby,rpastorin,rpikes,rpinilla,rpitter,rramirez,rrasual,rschkade,rtole,rtooker,saben,sackles,sarndt,saycock,sbemo,sbettridge,sbloise,sbonnie,sbrabyn,scocuzza,sdebry,senrico,sestergard,sgefroh,sgirsh,sgropper,sgunder,sgurski,shaith,sherzberg,showe,sjankauskas,skanjirathinga,skoegler,slaningham,slaudeman,slerew,smccaie,smillian,smullowney,snotari,spolmer,srees,srubenfield,sscheiern,sskone,sskyers,sspagnuolo,sstough,sstuemke,svandewalle,svielle,svogler,svongal,swoodie,tabdelal,tairth,tbagne,tbattista,tboxx,tcacal,tcossa,tcrissinger,tdonathan,teliades,tfalconeri,tfetherston,tgelen,tgindhart,tguinnip,tharr,thelfritz,thoch,thynson,tkeala,tkelly,tkhora,tlana,tlowers,tmalecki,tmarkus,tmccaffity,tmccamish,tmcmickle,tmelland,tmorr,tmurata,tmysinger,tnaillon,tnitzel,tpaa,tplatko,tredfearn,tsablea,tsann,tschnepel,tsearle,tsepulueda,tsowells,tstalworth,tvehrs,tvrooman,tyounglas,ualway,uazatyan,ubenken,ubieniek,ubynum,udatu,uednilao,ueriks,uflander,ugerpheide,ugreenberg,uhayakawa,uholecek,ulanigan,umarbury,umosser,upater,upellam,uransford,urosentrance,uschweyen,usevera,uslavinski,uspittler,uvanmatre,uwalpole,uweyand,vbaldasaro,vbigalow,vbonder,vburton,vchevalier,vcrofton,vdesir,vdolan,veisenhardt,vemily,venfort,vfeigel,vglidden,vkrug,vlubic,vmaynard,vmedici,vnazzal,vnery,vpeairs,vpender,vpiraino,vrodick,vrunyon,vsefcovic,vstirman,vtowell,vtresch,vtrumpp,vwabasha,vwaltmann,vwisinger,vwokwicz,wbrill,wclokecloak,wconces,wconstantino,wcreggett,wdagrella,wdevenish,wdovey,wenglander,werrick,wesguerra,wganther,wkhazaleh,wleiva,wlynch,wmailey,wmendell,wnunziata,wottesen,wselim,wstjean,wtruman,wvalcin,wvermeulen,xeppley,xlantey,xrahaim,yautin,ycerasoli,ycobetto,ycostaneda,yduft,yeven,yfrymoyer,ygockel,yhenriques,ykimbel,yolivier,yschmuff,ysnock,yvdberg,zanderlik,zborgmeyer,zbuscaglia,zculp,zfarler,zhaulk,zkutchera,zmeeker,zneeb,zratti,zscammahorn,zvagt,zwinterbottom
EOM

fi  # end of group tests

###########################################################################

if grep '^hosts.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing hosts..."

check "getent hosts testhost" << EOM
10.0.0.1        testhost testhostalias
EOM

check "getent hosts testhostalias" << EOM
10.0.0.1        testhost testhostalias
EOM

# check hostname with different case
check "getent hosts TESTHOST" << EOM
10.0.0.1        testhost testhostalias
EOM

check "getent hosts 10.0.0.1" << EOM
10.0.0.1        testhost testhostalias
EOM

check "getent hosts | grep testhost" << EOM
10.0.0.1        testhost testhostalias
EOM

# TODO: add more tests for IPv6 support

fi  # end of hosts tests

###########################################################################

if grep '^netgroup.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing netgroup..."

# check netgroup lookup of test netgroup
check "getent netgroup tstnetgroup" << EOM
tstnetgroup          ( , arthur, ) (noot, , )
EOM

# check netgroup lookup with different case
# Note: this should return nothing at all (this is a bug)
check "getent netgroup TSTNETGROUP" << EOM
TSTNETGROUP
EOM

fi  # end of netgroup tests

###########################################################################

if grep '^networks.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing networks..."

check "getent networks testnet" << EOM
testnet               10.0.0.0
EOM

# check network name with different case
check "getent networks TESTNET" << EOM
testnet               10.0.0.0
EOM

check "getent networks 10.0.0.0" << EOM
testnet               10.0.0.0
EOM

check "getent networks | grep testnet" << EOM
testnet               10.0.0.0
EOM

fi  # end of networks tests

###########################################################################

if grep '^passwd.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing passwd..."

check "getent passwd ecolden" << EOM
ecolden:x:5972:1000:Estelle Colden:/home/ecolden:/bin/bash
EOM

check "getent passwd arthur" << EOM
arthur:x:1000:100:Arthur de Jong:/home/arthur:/bin/bash
EOM

# check username with different case
check "getent passwd ARTHUR" << EOM
EOM

check "getent passwd 4089" << EOM
jguzzetta:x:4089:1000:Josephine Guzzetta:/home/jguzzetta:/bin/bash
EOM

# count the number of passwd entries in the 4000-5999 range
check "getent passwd | grep -c ':x:[45][0-9][0-9][0-9]:'" << EOM
2000
EOM

fi  # end of passwd tests

###########################################################################

if grep '^protocols.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing protocols..."

check "getent protocols protfoo" << EOM
protfoo               253 protfooalias
EOM

check "getent protocols protfooalias" << EOM
protfoo               253 protfooalias
EOM

# check protocol with different case
check "getent protocols PROTFOO" << EOM
EOM

# test protocol alias with different case
check "getent protocols PROTFOOALIAS" << EOM
EOM

check "getent protocols 253" << EOM
protfoo               253 protfooalias
EOM

check "getent protocols icmp" << EOM
icmp                  1 ICMP
EOM

check "getent protocols | grep protfoo" << EOM
protfoo               253 protfooalias
EOM

fi  # end of protocols tests

###########################################################################

if grep '^rpc.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing rpc..."

check "getent rpc rpcfoo" << EOM
rpcfoo          160002  rpcfooalias
EOM

check "getent rpc rpcfooalias" << EOM
rpcfoo          160002  rpcfooalias
EOM

# test rpc name with different case
check "getent rpc RPCFOO" << EOM
EOM

check "getent rpc 160002" << EOM
rpcfoo          160002  rpcfooalias
EOM

check "getent rpc | grep rpcfoo" << EOM
rpcfoo          160002  rpcfooalias
EOM

fi  # end of rpc tests

###########################################################################

if grep '^services.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing services..."

check "getent services foosrv" << EOM
foosrv                15349/tcp
EOM

check "getent services foosrv/tcp" << EOM
foosrv                15349/tcp
EOM

check "getent services foosrv/udp" << EOM
EOM

# check with different case
check "getent services FOOSRV" << EOM
EOM

# check protocol name case sensitivity (TCP is commonly an alias)
check "getent services foosrv/tCp" << EOM
EOM

check "getent services 15349/tcp" << EOM
foosrv                15349/tcp
EOM

check "getent services 15349/udp" << EOM
EOM

check "getent services barsrv" << EOM
barsrv                15350/tcp
EOM

check "getent services barsrv/tcp" << EOM
barsrv                15350/tcp
EOM

check "getent services barsrv/udp" << EOM
barsrv                15350/udp
EOM

check "getent services | egrep '(foo|bar)srv' | sort" << EOM
barsrv                15350/tcp
barsrv                15350/udp
foosrv                15349/tcp
EOM

check "getent services sssin" << EOM
sssin                 5000/tcp SSSIN
EOM

check "getent services SSSIN" << EOM
sssin                 5000/tcp SSSIN
EOM

check "getent services | wc -l" << EOM
`grep -c '^[^#].' /etc/services | awk '{print $1 + 4}'`
EOM

fi  # end of services tests

###########################################################################

if grep '^shadow.*ldap' /etc/nsswitch.conf > /dev/null 2>&1
then
echo "test_nsscmds.sh: testing shadow..."

# NOTE: the output of this should depend on whether we are root or not

check "getent shadow ecordas" << EOM
ecordas:*::::7:2::0
EOM

check "getent shadow adishaw" << EOM
adishaw:*:12302:::7:2::0
EOM

# check case-sensitivity
check "getent shadow ADISHAW" << EOM
EOM

# check if the number of passwd entries matches the number of shadow entries
check "getent shadow | wc -l" << EOM
`getent passwd | wc -l`
EOM

# check if the names of users match between passwd and shadow
getent passwd | sed 's/:.*//' | sort | \
  check "getent shadow | sed 's/:.*//' | sort"

fi  # end of shadow tests

###########################################################################
# determine the result

if [ $FAIL -eq 0 ]
then
  echo "test_nsscmds.sh: all tests passed"
  exit 0
else
  echo "test_nsscmds.sh: $FAIL TESTS FAILED"
  exit 1
fi
