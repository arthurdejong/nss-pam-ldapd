#!/bin/sh

# test_ldapcmds.sh - simple test script to test lookups
#
# Copyright (C) 2017 Arthur de Jong
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

set -e

# find source directory
srcdir="${srcdir-`dirname "$0"`}"
top_srcdir="${top_srcdir-${srcdir}/..}"
builddir="${builddir-`dirname "$0"`}"
top_builddir="${top_builddir-${builddir}/..}"
python="${PYTHON-python}"
PYTHONPATH="${top_srcdir}/utils:${top_builddir}/utils"
export PYTHONPATH

# ensure that we are running in the test environment
"$srcdir/testenv.sh" check_nslcd || exit 77

# if Python is missing, ignore
if [ -z "${python}" ] || ! ${python} --version > /dev/null 2> /dev/null
then
  echo "Python (${python}) not found"
  exit 77
fi

# the total number of errors
FAIL=0

getent_ldap() {
  ${python} -m getent ${1:+"$@"}
}

check() {
  # the command to execute
  cmd="$1"
  # save the expected output
  expectfile=`mktemp -t expected.XXXXXX 2> /dev/null || tempfile -s .expected 2> /dev/null`
  cat > "$expectfile"
  # run the command
  echo 'test_nsscmds.sh: checking "'"$cmd"'"'
  actualfile=`mktemp -t actual.XXXXXX 2> /dev/null || tempfile -s .actual 2> /dev/null`
  eval "$(echo $cmd | sed 's/getent.ldap/getent_ldap/g')" > "$actualfile" 2>&1 || true
  # check for differences
  diff -Nauwi "$expectfile" "$actualfile" || FAIL=`expr $FAIL + 1`
  # remove temporary files
  rm "$expectfile" "$actualfile"
}

###########################################################################

echo "test_ldapcmds.sh: testing aliases..."

# check all aliases
check "getent.ldap aliases|sort" << EOM
bar2:           foobar@example.com
bar:            foobar@example.com
foo:            bar@example.com
EOM

# get alias by name
check "getent.ldap aliases foo" << EOM
foo:            bar@example.com
EOM

# get alias by second name
check "getent.ldap aliases bar2" << EOM
bar2:           foobar@example.com
EOM

# get alias by different case
check "getent.ldap aliases FOO" << EOM
foo:            bar@example.com
EOM

###########################################################################

echo "test_ldapcmds.sh: testing ether..."

# get an entry by hostname
check "getent.ldap ethers testhost" << EOM
0:18:8a:54:1a:8e testhost
EOM

# get an entry by alias name
check "getent.ldap ethers testhostalias" << EOM
0:18:8a:54:1a:8e testhostalias
EOM

# get an entry by hostname with different case
check "getent.ldap ethers TESTHOST" << EOM
0:18:8a:54:1a:8e testhost
EOM

# get an entry by ethernet address
check "getent.ldap ethers 0:18:8a:54:1a:8b" << EOM
0:18:8a:54:1a:8b testhost2
EOM

# get all ethers (unsupported)
check "getent.ldap ethers|sort" << EOM
0:18:8a:54:1a:8b testhost2
0:18:8a:54:1a:8e testhost
0:18:8a:54:1a:8e testhostalias
EOM

###########################################################################

echo "test_ldapcmds.sh: testing group..."

# function to sort group members of a group
sortgroup() {
  while read line
  do
    group="`echo "$line" | sed 's/^\([^:]*:[^:]*:[^:]*\).*$/\1:/'`"
    members="`echo "$line" | sed -n 's/^[^:]*:[^:]*:[^:]*:\(.*\)$/\1/p' | tr ',' '\n' | sort | tr '\n' ','`"
    members="`echo "$members" | sed 's/,$//'`"
    echo "${group}${members}"
  done
}

check "getent.ldap group testgroup | sortgroup" << EOM
testgroup:*:6100:arthur,test,testuser4
EOM

check "getent.ldap group users" << EOM
users:*:100:arthur,test
EOM

# group with different case should not be found
check "getent.ldap group TESTGROUP" << EOM
EOM

check "getent.ldap group 6100 | sortgroup" << EOM
testgroup:*:6100:arthur,test,testuser4
EOM

check "getent.ldap group.bymember arthur | sed 's/:.*//' | sort" << EOM
grp10
grp11
grp12
grp13
grp14
grp15
grp16
grp17
grp18
grp4
grp5
grp6
grp7
grp8
grp9
testgroup
testgroup2
users
EOM

check "getent.ldap group.bymember testuser4 | sed 's/:.*//' | sort" << EOM
testgroup
testgroup2
EOM

check "getent.ldap group | egrep '^(testgroup|users):' | sortgroup" << EOM
testgroup:*:6100:arthur,test,testuser4
users:*:100:arthur,test
EOM

check "getent.ldap group | wc -l" << EOM
23
EOM

check "getent.ldap group | grep ^largegroup | sortgroup" << EOM
largegroup:*:1005:akraskouskas,alat,ameisinger,bdevera,behrke,bmoldan,btempel,cjody,clouder,cmanno,dbye,dciviello,dfirpo,dgivliani,dgosser,emcquiddy,enastasi,fcunard,gcubbison,gdaub,gdreitzler,ghanauer,gpomerance,gsusoev,gtinnel,gvollrath,gzuhlke,hgalavis,hhaffey,hhydrick,hmachesky,hpaek,hpolk,hsweezer,htomlinson,hzagami,igurwell,ihashbarger,jyeater,kbradbury,khathway,kklavetter,lbuchtel,lgandee,lkhubba,lmauracher,lseehafer,lvittum,mblanchet,mbodley,mciaccia,mjuris,ndipanfilo,nfilipek,nfunchess,ngata,ngullett,nkraker,nriofrio,nroepke,nrybij,oclunes,oebrani,okveton,osaines,otrevor,pdossous,phaye,psowa,purquilla,rkoonz,rlatessa,rworkowski,sdebry,sgurski,showe,slaforge,tabdelal,testusr2,testusr3,tfalconeri,tpaa,uschweyen,utrezize,vchevalier,vdelnegro,vleyton,vmedici,vmigliori,vpender,vwaltmann,wbrettschneide,wselim,wvalcin,wworf,yautin,ykisak,zgingrich,znightingale,zwinterbottom
EOM

check "getent.ldap group largegroup | sortgroup" << EOM
largegroup:*:1005:akraskouskas,alat,ameisinger,bdevera,behrke,bmoldan,btempel,cjody,clouder,cmanno,dbye,dciviello,dfirpo,dgivliani,dgosser,emcquiddy,enastasi,fcunard,gcubbison,gdaub,gdreitzler,ghanauer,gpomerance,gsusoev,gtinnel,gvollrath,gzuhlke,hgalavis,hhaffey,hhydrick,hmachesky,hpaek,hpolk,hsweezer,htomlinson,hzagami,igurwell,ihashbarger,jyeater,kbradbury,khathway,kklavetter,lbuchtel,lgandee,lkhubba,lmauracher,lseehafer,lvittum,mblanchet,mbodley,mciaccia,mjuris,ndipanfilo,nfilipek,nfunchess,ngata,ngullett,nkraker,nriofrio,nroepke,nrybij,oclunes,oebrani,okveton,osaines,otrevor,pdossous,phaye,psowa,purquilla,rkoonz,rlatessa,rworkowski,sdebry,sgurski,showe,slaforge,tabdelal,testusr2,testusr3,tfalconeri,tpaa,uschweyen,utrezize,vchevalier,vdelnegro,vleyton,vmedici,vmigliori,vpender,vwaltmann,wbrettschneide,wselim,wvalcin,wworf,yautin,ykisak,zgingrich,znightingale,zwinterbottom
EOM

check "getent.ldap group | grep ^hugegroup | sortgroup" << EOM
hugegroup:*:1006:ablackstock,abortignon,achhor,ademosthenes,adenicola,adishaw,aesbensen,aferge,afredin,afuchs,agarbett,agimm,agordner,ahandy,ajaquess,akertzman,akomsthoeft,akraskouskas,akravetz,alamour,alat,alienhard,amanganelli,amaslyn,amayorga,amccroskey,amcgraw,amckinney,ameisinger,aponcedeleon,apurdon,areid,arosel,ascheno,ascovel,asemons,ashuey,asivley,astrunk,atollefsrud,atonkin,awhitt,aziernicki,badair,baigner,bbeckfield,bbrenton,bcoletta,bcolorado,bdadds,bdaughenbaugh,bdevera,bdominga,behrke,beon,bfishbeck,bgavagan,bguthary,bharnois,bhelverson,bjolly,blovig,bluellen,bmadamba,bmarlin,bmarszalek,bmicklos,bmoling,bouten,bphou,bpinedo,brodgerson,broher,bromano,bscadden,bsibal,bstrede,bswantak,btempel,btheim,bveeneman,bwinterton,bwynes,cabare,carguellez,cbarlup,cbartnick,cbelardo,cbleimehl,cbotdorf,cbourek,cbrechbill,cbrom,ccyganiewicz,cdeckard,cdegravelle,cdickes,cdrumm,cfasone,cflenner,cfleurantin,cgaler,cgalinol,cgaudette,cghianni,charriman,cjody,cjuntunen,ckerska,ckistenmacher,cklem,ckodish,clapenta,clewicki,clouder,cmafnas,cmanno,cmcanulty,cmellberg,cmiramon,cnabzdyk,cnoriego,cpaccione,cpalmios,cparee,cpencil,cpentreath,cpinela,cpluid,critchie,cscullion,csever,csoomaroo,cspilis,cswigert,ctenny,ctetteh,ctuzzo,cwank,cweiss,dasiedu,daubert,dbarriball,dbertels,dblazejewski,dcaltabiano,dciullo,ddeguire,ddigerolamo,denriquez,deshmon,dfirpo,dflore,dfollman,dgiacomazzi,dgivliani,dgosser,dhammontree,dhendon,dhindsman,dholdaway,dlablue,dlanois,dlargo,dledenbach,dlongbotham,dloubier,dmahapatra,dmarchizano,dmcgillen,dminozzi,dnegri,dpebbles,draymundo,dscheurer,dsharr,dsherard,dsteever,dtashjian,dtornow,dtuholski,dwittlinger,dzurek,eaguire,eathey,ebattee,ebeachem,eberkman,ebusk,ecelestin,ecolden,ecordas,ediga,edrinkwater,edurick,egospatrick,egrago,ehathcock,ehindbaugh,ejeppesen,ekalfas,ekenady,ekeuper,eklein,eklunder,ekurter,emanikowski,emargulis,emcquiddy,emehta,eorsten,eparham,epeterson,epoinelli,erathert,erostad,eserrett,esheehan,esonia,esproull,esthill,estockwin,etunby,ewicks,ewilles,ewismer,ewuitschick,eyounglas,eziebert,fagro,faleo,farquette,fbeatrice,fberra,fberyman,fbielecki,fburrough,fcha,fcunard,ffigert,fgoben,fgrashot,fhain,fhalon,fkeef,fmarchi,fmilsaps,fnottage,fparness,fplayfair,fsapien,fsavela,fsirianni,fsplinter,fsunderland,fsymmonds,fthein,fvallian,fvascones,fverfaille,fvinal,fwidhalm,gallanson,gapkin,garchambeault,gbitar,gbolay,gcarlini,gcervantez,gchounlapane,gclapham,gcobane,gconver,gcukaj,gcummer,gcurnutt,gdaub,gdeblasio,gdeyarmond,gdrilling,gearnshaw,gfaire,gfedewa,ggehrke,ggillim,ghann,ghelderman,ghumbles,gishii,gjankowiak,gkerens,glafontaine,gloebs,gmackinder,gmassi,gmilian,gmings,gmoen,gparkersmith,gpomerance,gportolese,greiff,gsantella,gschaumburg,gshrode,gtinnel,guresti,gvollrath,gwaud,habby,hbastidos,hbetterman,hbickford,hbraim,hbrandow,hbrehmer,hbukovsky,hcafourek,hcarrizal,hchaviano,hcintron,hcowles,hcusta,hdoiel,hdyner,hfludd,hgalavis,hhaffey,hhagee,hhartranft,hholyfield,hhysong,hkarney,hkinderknecht,hkippes,hkohlmeyer,hlauchaire,hlemon,hlichota,hliverman,hloftis,hlynema,hmateer,hmatonak,hmiazga,hmogush,hmuscaro,hpalmquist,hpimpare,hpolintan,hrapisura,hrenart,hriech,hsabol,hschelb,hschoepfer,hspiry,hstreitnatter,hsweezer,htilzer,htomlinson,htsuha,hvannette,hveader,hwestermark,hwoodert,hzagami,hzinda,iambrosino,ibeto,ibreitbart,ibuzo,ibyles,ichewning,icoard,ideveyra,ienglert,igizzi,ihalford,ihanneman,ihegener,ihernan,iherrarte,ihimmelwright,ihoa,iiffert,ikadar,ikulbida,ilacourse,ilamberth,ilawbaugh,ileaman,ilevian,imarungo,imcbay,imensah,imicthell,imillin,imuehl,inarain,iogasawara,iroiger,iseipel,isowder,isplonskowski,istallcup,istarring,isteinlicht,ithum,ivanschaack,iweibe,iyorgey,iyorks,jamber,jappleyard,jbielicki,jbjorkman,jcaroll,jdodge,jeuresti,jeverton,jglotzbecker,jherkenratt,jholzmiller,jjumalon,jkimpton,jknight,jlebouf,jlunney,jmartha,jmarugg,jmatty,joligee,jquicksall,jrees,jreigh,jroman,jscheitlin,jseen,jsegundo,jsenavanh,jskafec,jspohn,jsweezy,jvillaire,jwinterton,jzych,kaanerud,kalguire,kbarnthouse,kbartolet,kbattershell,kbrevitz,kbrugal,kcofrancesco,kcomparoni,kconkey,kdevincent,kepps,kfaure,kfend,kgarced,kgremminger,khartness,kheadlon,khovanesian,kjoslyn,klitehiser,klundsten,klurie,kmallach,kmandolfo,kmarzili,kmayoras,kmcardle,kmcguire,kmedcaf,kmeester,kmisove,kmoesch,kmosko,kmuros,kolexa,kottomaniello,kpalka,kpannunzio,kpenale,kpuebla,krahman,kseisler,kshippy,ksiering,ksollitto,ksparling,kstachurski,kthede,ktoni,ktriblett,ktuccio,ktuner,kwidrick,kwinterling,kwirght,laksamit,lautovino,lbanco,lbassin,lbove,lbuchtel,lcanestrini,lcaudell,lcavez,lcocherell,lcoulon,lcremer,leberhardt,lfarraj,lfichtner,lgadomski,lgandee,lgradilla,lhuggler,limbrogno,ljomes,lkimel,llarmore,llasher,lmadruga,lmauracher,lmcgeary,lmichaud,lmuehlberger,lnormand,lparrish,lpeagler,lpintor,lpitek,lpondexter,lrandall,lringuette,lschenkelberg,lschnorbus,lschollmeier,lseabold,lseehafer,lshilling,lsivic,lsobrino,lsous,lspielvogel,lvaleriano,lvanconant,lwedner,lyoula,mallmand,maustine,mbeagley,mbodley,mbravata,mcampagnone,mcaram,mcashett,mcasida,mcoch,mcolehour,mcontreras,mdanos,mdecourcey,mdedon,mdickinson,mdimaio,mdoering,mdyce,meconomides,mespinel,mfaeth,mfeil,mferandez,mfitzherbert,mgavet,mgayden,mground,mheilbrun,mhollings,mjeon,mkibler,mkofoed,mlaverde,mlenning,mlinak,mlinardi,mmangiamele,mmattu,mmcchristian,mmerriwether,mmesidor,mneubacher,moller,moser,mpanahon,mpark,mpellew,mpilon,mpizzaro,mpytko,mquigg,mredd,mrizer,mruppel,mrydelek,mskeele,mstirn,mswogger,mtanzi,mtintle,mvanbergen,mvanpelt,mvas,mvedder,mviverette,myokoyama,nagerton,nasmar,nbuford,nbugtong,ncermeno,nchrisman,nciucci,ndesautels,ndrumgole,nedgin,nendicott,nerbach,nevan,nforti,nfunchess,ngiesler,nglathar,ngrowney,ngullett,nhayer,nhelfinstine,nhija,ninnella,njordon,nkempon,nkubley,nlainhart,nlatchaw,nlemma,nlinarez,nlohmiller,nmccolm,nmoren,nnamanworth,nnickel,nousdahl,nphan,nramones,nranck,nridinger,nriofrio,nrybij,nrysavy,nschmig,nsiemonsma,nslaby,nspolar,nvyhnal,nwescott,nwiker,oahyou,oalthouse,obeaufait,obenallack,obercier,obihl,ocalleo,ochasten,oclunes,oconerly,ocrabbs,oebrani,ofelcher,ohatto,ohearl,ohedlund,ohoffert,ohove,ojerabek,okave,okveton,omalvaez,omasone,omatula,omcdaid,oolivarez,oosterhouse,opeet,opizzuti,opoch,oport,opuglisi,oreiss,osaber,oscarpello,oshough,ovibbert,owhelchel,owhitelow,pahles,pbascom,pbeckerdite,pbiggart,pbondroff,pbrentano,pcaposole,pcornn,pdauterman,pdech,pdischinger,pduitscher,pdulac,pdurando,pfavolise,pgiegerich,pgreenier,pgrybel,phalkett,pheathcock,phyer,pmineo,pminnis,ppedraja,ppeper,pphuaphes,prepasky,prowena,psabado,psalesky,pschrayter,psharits,psiroky,psundeen,pthornberry,ptoenjes,ptraweek,purquilla,pvierthaler,pvirelli,pviviani,pwademan,pwashuk,pwetherwax,pwhitmire,pwohlenhaus,pwutzke,qhanly,ralspach,rbernhagen,rbillingsly,rbloomstrand,rbrisby,rcheshier,rchevrette,rdubs,rdubuisson,redling,rfassinger,rfauerbach,rfidel,rginer,rgoonez,rgramby,rgriffies,rguinane,rheinzmann,rkraszewski,rlambertus,rlatessa,rlosinger,rmandril,rmcstay,rnordby,rpastorin,rpikes,rpinilla,rpitter,rramirez,rrasual,rschkade,rtole,rtooker,saben,sackles,sarndt,saycock,sbemo,sbettridge,sbloise,sbonnie,sbrabyn,scocuzza,sdebry,senrico,sestergard,sgefroh,sgirsh,sgropper,sgunder,sgurski,shaith,sherzberg,showe,sjankauskas,skanjirathinga,skoegler,slaningham,slaudeman,slerew,smccaie,smillian,smullowney,snotari,spolmer,srees,srubenfield,sscheiern,sskone,sskyers,sspagnuolo,sstough,sstuemke,svandewalle,svielle,svogler,svongal,swoodie,tabdelal,tairth,tbagne,tbattista,tboxx,tcacal,tcossa,tcrissinger,tdonathan,teliades,tfalconeri,tfetherston,tgelen,tgindhart,tguinnip,tharr,thelfritz,thoch,thynson,tkeala,tkelly,tkhora,tlana,tlowers,tmalecki,tmarkus,tmccaffity,tmccamish,tmcmickle,tmelland,tmorr,tmurata,tmysinger,tnaillon,tnitzel,tpaa,tplatko,tredfearn,tsablea,tsann,tschnepel,tsearle,tsepulueda,tsowells,tstalworth,tvehrs,tvrooman,tyounglas,ualway,uazatyan,ubenken,ubieniek,ubynum,udatu,uednilao,ueriks,uflander,ugerpheide,ugreenberg,uhayakawa,uholecek,ulanigan,umarbury,umosser,upater,upellam,uransford,urosentrance,uschweyen,usevera,uslavinski,uspittler,uvanmatre,uwalpole,uweyand,vbaldasaro,vbigalow,vbonder,vburton,vchevalier,vcrofton,vdesir,vdolan,veisenhardt,vemily,venfort,vfeigel,vglidden,vkrug,vlubic,vmaynard,vmedici,vnazzal,vnery,vpeairs,vpender,vpiraino,vrodick,vrunyon,vsefcovic,vstirman,vtowell,vtresch,vtrumpp,vwabasha,vwaltmann,vwisinger,vwokwicz,wbrill,wclokecloak,wconces,wconstantino,wcreggett,wdagrella,wdevenish,wdovey,wenglander,werrick,wesguerra,wganther,wkhazaleh,wleiva,wlynch,wmailey,wmendell,wnunziata,wottesen,wselim,wstjean,wtruman,wvalcin,wvermeulen,xeppley,xlantey,xrahaim,yautin,ycerasoli,ycobetto,ycostaneda,yduft,yeven,yfrymoyer,ygockel,yhenriques,ykimbel,yolivier,yschmuff,ysnock,yvdberg,zanderlik,zborgmeyer,zbuscaglia,zculp,zfarler,zhaulk,zkutchera,zmeeker,zneeb,zratti,zscammahorn,zvagt,zwinterbottom
EOM

check "getent.ldap group hugegroup | sortgroup" << EOM
hugegroup:*:1006:ablackstock,abortignon,achhor,ademosthenes,adenicola,adishaw,aesbensen,aferge,afredin,afuchs,agarbett,agimm,agordner,ahandy,ajaquess,akertzman,akomsthoeft,akraskouskas,akravetz,alamour,alat,alienhard,amanganelli,amaslyn,amayorga,amccroskey,amcgraw,amckinney,ameisinger,aponcedeleon,apurdon,areid,arosel,ascheno,ascovel,asemons,ashuey,asivley,astrunk,atollefsrud,atonkin,awhitt,aziernicki,badair,baigner,bbeckfield,bbrenton,bcoletta,bcolorado,bdadds,bdaughenbaugh,bdevera,bdominga,behrke,beon,bfishbeck,bgavagan,bguthary,bharnois,bhelverson,bjolly,blovig,bluellen,bmadamba,bmarlin,bmarszalek,bmicklos,bmoling,bouten,bphou,bpinedo,brodgerson,broher,bromano,bscadden,bsibal,bstrede,bswantak,btempel,btheim,bveeneman,bwinterton,bwynes,cabare,carguellez,cbarlup,cbartnick,cbelardo,cbleimehl,cbotdorf,cbourek,cbrechbill,cbrom,ccyganiewicz,cdeckard,cdegravelle,cdickes,cdrumm,cfasone,cflenner,cfleurantin,cgaler,cgalinol,cgaudette,cghianni,charriman,cjody,cjuntunen,ckerska,ckistenmacher,cklem,ckodish,clapenta,clewicki,clouder,cmafnas,cmanno,cmcanulty,cmellberg,cmiramon,cnabzdyk,cnoriego,cpaccione,cpalmios,cparee,cpencil,cpentreath,cpinela,cpluid,critchie,cscullion,csever,csoomaroo,cspilis,cswigert,ctenny,ctetteh,ctuzzo,cwank,cweiss,dasiedu,daubert,dbarriball,dbertels,dblazejewski,dcaltabiano,dciullo,ddeguire,ddigerolamo,denriquez,deshmon,dfirpo,dflore,dfollman,dgiacomazzi,dgivliani,dgosser,dhammontree,dhendon,dhindsman,dholdaway,dlablue,dlanois,dlargo,dledenbach,dlongbotham,dloubier,dmahapatra,dmarchizano,dmcgillen,dminozzi,dnegri,dpebbles,draymundo,dscheurer,dsharr,dsherard,dsteever,dtashjian,dtornow,dtuholski,dwittlinger,dzurek,eaguire,eathey,ebattee,ebeachem,eberkman,ebusk,ecelestin,ecolden,ecordas,ediga,edrinkwater,edurick,egospatrick,egrago,ehathcock,ehindbaugh,ejeppesen,ekalfas,ekenady,ekeuper,eklein,eklunder,ekurter,emanikowski,emargulis,emcquiddy,emehta,eorsten,eparham,epeterson,epoinelli,erathert,erostad,eserrett,esheehan,esonia,esproull,esthill,estockwin,etunby,ewicks,ewilles,ewismer,ewuitschick,eyounglas,eziebert,fagro,faleo,farquette,fbeatrice,fberra,fberyman,fbielecki,fburrough,fcha,fcunard,ffigert,fgoben,fgrashot,fhain,fhalon,fkeef,fmarchi,fmilsaps,fnottage,fparness,fplayfair,fsapien,fsavela,fsirianni,fsplinter,fsunderland,fsymmonds,fthein,fvallian,fvascones,fverfaille,fvinal,fwidhalm,gallanson,gapkin,garchambeault,gbitar,gbolay,gcarlini,gcervantez,gchounlapane,gclapham,gcobane,gconver,gcukaj,gcummer,gcurnutt,gdaub,gdeblasio,gdeyarmond,gdrilling,gearnshaw,gfaire,gfedewa,ggehrke,ggillim,ghann,ghelderman,ghumbles,gishii,gjankowiak,gkerens,glafontaine,gloebs,gmackinder,gmassi,gmilian,gmings,gmoen,gparkersmith,gpomerance,gportolese,greiff,gsantella,gschaumburg,gshrode,gtinnel,guresti,gvollrath,gwaud,habby,hbastidos,hbetterman,hbickford,hbraim,hbrandow,hbrehmer,hbukovsky,hcafourek,hcarrizal,hchaviano,hcintron,hcowles,hcusta,hdoiel,hdyner,hfludd,hgalavis,hhaffey,hhagee,hhartranft,hholyfield,hhysong,hkarney,hkinderknecht,hkippes,hkohlmeyer,hlauchaire,hlemon,hlichota,hliverman,hloftis,hlynema,hmateer,hmatonak,hmiazga,hmogush,hmuscaro,hpalmquist,hpimpare,hpolintan,hrapisura,hrenart,hriech,hsabol,hschelb,hschoepfer,hspiry,hstreitnatter,hsweezer,htilzer,htomlinson,htsuha,hvannette,hveader,hwestermark,hwoodert,hzagami,hzinda,iambrosino,ibeto,ibreitbart,ibuzo,ibyles,ichewning,icoard,ideveyra,ienglert,igizzi,ihalford,ihanneman,ihegener,ihernan,iherrarte,ihimmelwright,ihoa,iiffert,ikadar,ikulbida,ilacourse,ilamberth,ilawbaugh,ileaman,ilevian,imarungo,imcbay,imensah,imicthell,imillin,imuehl,inarain,iogasawara,iroiger,iseipel,isowder,isplonskowski,istallcup,istarring,isteinlicht,ithum,ivanschaack,iweibe,iyorgey,iyorks,jamber,jappleyard,jbielicki,jbjorkman,jcaroll,jdodge,jeuresti,jeverton,jglotzbecker,jherkenratt,jholzmiller,jjumalon,jkimpton,jknight,jlebouf,jlunney,jmartha,jmarugg,jmatty,joligee,jquicksall,jrees,jreigh,jroman,jscheitlin,jseen,jsegundo,jsenavanh,jskafec,jspohn,jsweezy,jvillaire,jwinterton,jzych,kaanerud,kalguire,kbarnthouse,kbartolet,kbattershell,kbrevitz,kbrugal,kcofrancesco,kcomparoni,kconkey,kdevincent,kepps,kfaure,kfend,kgarced,kgremminger,khartness,kheadlon,khovanesian,kjoslyn,klitehiser,klundsten,klurie,kmallach,kmandolfo,kmarzili,kmayoras,kmcardle,kmcguire,kmedcaf,kmeester,kmisove,kmoesch,kmosko,kmuros,kolexa,kottomaniello,kpalka,kpannunzio,kpenale,kpuebla,krahman,kseisler,kshippy,ksiering,ksollitto,ksparling,kstachurski,kthede,ktoni,ktriblett,ktuccio,ktuner,kwidrick,kwinterling,kwirght,laksamit,lautovino,lbanco,lbassin,lbove,lbuchtel,lcanestrini,lcaudell,lcavez,lcocherell,lcoulon,lcremer,leberhardt,lfarraj,lfichtner,lgadomski,lgandee,lgradilla,lhuggler,limbrogno,ljomes,lkimel,llarmore,llasher,lmadruga,lmauracher,lmcgeary,lmichaud,lmuehlberger,lnormand,lparrish,lpeagler,lpintor,lpitek,lpondexter,lrandall,lringuette,lschenkelberg,lschnorbus,lschollmeier,lseabold,lseehafer,lshilling,lsivic,lsobrino,lsous,lspielvogel,lvaleriano,lvanconant,lwedner,lyoula,mallmand,maustine,mbeagley,mbodley,mbravata,mcampagnone,mcaram,mcashett,mcasida,mcoch,mcolehour,mcontreras,mdanos,mdecourcey,mdedon,mdickinson,mdimaio,mdoering,mdyce,meconomides,mespinel,mfaeth,mfeil,mferandez,mfitzherbert,mgavet,mgayden,mground,mheilbrun,mhollings,mjeon,mkibler,mkofoed,mlaverde,mlenning,mlinak,mlinardi,mmangiamele,mmattu,mmcchristian,mmerriwether,mmesidor,mneubacher,moller,moser,mpanahon,mpark,mpellew,mpilon,mpizzaro,mpytko,mquigg,mredd,mrizer,mruppel,mrydelek,mskeele,mstirn,mswogger,mtanzi,mtintle,mvanbergen,mvanpelt,mvas,mvedder,mviverette,myokoyama,nagerton,nasmar,nbuford,nbugtong,ncermeno,nchrisman,nciucci,ndesautels,ndrumgole,nedgin,nendicott,nerbach,nevan,nforti,nfunchess,ngiesler,nglathar,ngrowney,ngullett,nhayer,nhelfinstine,nhija,ninnella,njordon,nkempon,nkubley,nlainhart,nlatchaw,nlemma,nlinarez,nlohmiller,nmccolm,nmoren,nnamanworth,nnickel,nousdahl,nphan,nramones,nranck,nridinger,nriofrio,nrybij,nrysavy,nschmig,nsiemonsma,nslaby,nspolar,nvyhnal,nwescott,nwiker,oahyou,oalthouse,obeaufait,obenallack,obercier,obihl,ocalleo,ochasten,oclunes,oconerly,ocrabbs,oebrani,ofelcher,ohatto,ohearl,ohedlund,ohoffert,ohove,ojerabek,okave,okveton,omalvaez,omasone,omatula,omcdaid,oolivarez,oosterhouse,opeet,opizzuti,opoch,oport,opuglisi,oreiss,osaber,oscarpello,oshough,ovibbert,owhelchel,owhitelow,pahles,pbascom,pbeckerdite,pbiggart,pbondroff,pbrentano,pcaposole,pcornn,pdauterman,pdech,pdischinger,pduitscher,pdulac,pdurando,pfavolise,pgiegerich,pgreenier,pgrybel,phalkett,pheathcock,phyer,pmineo,pminnis,ppedraja,ppeper,pphuaphes,prepasky,prowena,psabado,psalesky,pschrayter,psharits,psiroky,psundeen,pthornberry,ptoenjes,ptraweek,purquilla,pvierthaler,pvirelli,pviviani,pwademan,pwashuk,pwetherwax,pwhitmire,pwohlenhaus,pwutzke,qhanly,ralspach,rbernhagen,rbillingsly,rbloomstrand,rbrisby,rcheshier,rchevrette,rdubs,rdubuisson,redling,rfassinger,rfauerbach,rfidel,rginer,rgoonez,rgramby,rgriffies,rguinane,rheinzmann,rkraszewski,rlambertus,rlatessa,rlosinger,rmandril,rmcstay,rnordby,rpastorin,rpikes,rpinilla,rpitter,rramirez,rrasual,rschkade,rtole,rtooker,saben,sackles,sarndt,saycock,sbemo,sbettridge,sbloise,sbonnie,sbrabyn,scocuzza,sdebry,senrico,sestergard,sgefroh,sgirsh,sgropper,sgunder,sgurski,shaith,sherzberg,showe,sjankauskas,skanjirathinga,skoegler,slaningham,slaudeman,slerew,smccaie,smillian,smullowney,snotari,spolmer,srees,srubenfield,sscheiern,sskone,sskyers,sspagnuolo,sstough,sstuemke,svandewalle,svielle,svogler,svongal,swoodie,tabdelal,tairth,tbagne,tbattista,tboxx,tcacal,tcossa,tcrissinger,tdonathan,teliades,tfalconeri,tfetherston,tgelen,tgindhart,tguinnip,tharr,thelfritz,thoch,thynson,tkeala,tkelly,tkhora,tlana,tlowers,tmalecki,tmarkus,tmccaffity,tmccamish,tmcmickle,tmelland,tmorr,tmurata,tmysinger,tnaillon,tnitzel,tpaa,tplatko,tredfearn,tsablea,tsann,tschnepel,tsearle,tsepulueda,tsowells,tstalworth,tvehrs,tvrooman,tyounglas,ualway,uazatyan,ubenken,ubieniek,ubynum,udatu,uednilao,ueriks,uflander,ugerpheide,ugreenberg,uhayakawa,uholecek,ulanigan,umarbury,umosser,upater,upellam,uransford,urosentrance,uschweyen,usevera,uslavinski,uspittler,uvanmatre,uwalpole,uweyand,vbaldasaro,vbigalow,vbonder,vburton,vchevalier,vcrofton,vdesir,vdolan,veisenhardt,vemily,venfort,vfeigel,vglidden,vkrug,vlubic,vmaynard,vmedici,vnazzal,vnery,vpeairs,vpender,vpiraino,vrodick,vrunyon,vsefcovic,vstirman,vtowell,vtresch,vtrumpp,vwabasha,vwaltmann,vwisinger,vwokwicz,wbrill,wclokecloak,wconces,wconstantino,wcreggett,wdagrella,wdevenish,wdovey,wenglander,werrick,wesguerra,wganther,wkhazaleh,wleiva,wlynch,wmailey,wmendell,wnunziata,wottesen,wselim,wstjean,wtruman,wvalcin,wvermeulen,xeppley,xlantey,xrahaim,yautin,ycerasoli,ycobetto,ycostaneda,yduft,yeven,yfrymoyer,ygockel,yhenriques,ykimbel,yolivier,yschmuff,ysnock,yvdberg,zanderlik,zborgmeyer,zbuscaglia,zculp,zfarler,zhaulk,zkutchera,zmeeker,zneeb,zratti,zscammahorn,zvagt,zwinterbottom
EOM

check "getent.ldap group nstgrp1 | sortgroup" << EOM
nstgrp1:*:800:testusr2
EOM

check "getent.ldap group nstgrp2 | sortgroup" << EOM
nstgrp2:*:801:testusr2,testusr3
EOM

check "getent.ldap group nstgrp3 | sortgroup" << EOM
nstgrp3:*:802:testusr2,testusr3
EOM

check "getent.ldap group.bymember testusr2 | sed 's/:.*//' | sort" << EOM
largegroup
nstgrp1
nstgrp2
nstgrp3
testgroup2
EOM

check "getent.ldap group.bymember testusr3 | sed 's/:.*//' | sort" << EOM
largegroup
nstgrp2
nstgrp3
EOM

###########################################################################

echo "test_ldapcmds.sh: testing hosts..."

check "getent.ldap hosts testhost" << EOM
192.0.2.123        testhost testhostalias
EOM

check "getent.ldap hosts testhostalias" << EOM
192.0.2.123        testhost testhostalias
EOM

# check hostname with different case
check "getent.ldap hosts TESTHOST" << EOM
192.0.2.123        testhost testhostalias
EOM

check "getent.ldap hosts 192.0.2.123" << EOM
192.0.2.123        testhost testhostalias
EOM

check "getent.ldap hosts | grep testhost | sort" << EOM
192.0.2.123        testhost testhostalias
192.0.2.124        testhost2
192.0.2.126        testhost4
2001:db8::7e27:ac1d testhost4
2001:db8::dead:beef testhost2
2001:db8::feed:c0de testhost3
EOM

check "getent.ldap hosts 2001:db8::dead:beef | sort" << EOM
192.0.2.124     testhost2
2001:db8::dead:beef testhost2
EOM

check "getent.ldap hostsv4 testhost2" << EOM
192.0.2.124     testhost2
EOM

check "getent.ldap hostsv6 testhost2" << EOM
2001:db8::dead:beef testhost2
EOM

check "getent.ldap hostsv4 192.0.2.124" << EOM
192.0.2.124     testhost2
EOM

check "getent.ldap hostsv6 2001:db8::dead:beef" << EOM
2001:db8::dead:beef testhost2
EOM

check "getent.ldap hostsv4 2001:db8::dead:beef" << EOM
EOM

check "getent.ldap hostsv6 192.0.2.124" << EOM
EOM

###########################################################################

echo "test_ldapcmds.sh: testing netgroup..."

# check netgroup lookup of test netgroup
check "getent.ldap netgroup tstnetgroup" << EOM
tstnetgroup          ( , arthur, ) (noot, , )
EOM

# check netgroup lookup with different case
check "getent.ldap netgroup TSTNETGROUP" << EOM
EOM

# check netgroup lookup of test netgroup without recursion
check "getent.ldap netgroup.norec tstnetgroup" << EOM
tstnetgroup     tst3netgroup tst2netgroup (, arthur, )
EOM

###########################################################################

echo "test_ldapcmds.sh: testing networks..."

check "getent.ldap networks testnet" << EOM
testnet               192.0.2.0
EOM

# check network name with different case
check "getent.ldap networks TESTNET" << EOM
testnet               192.0.2.0
EOM

check "getent.ldap networks 192.0.2.0" << EOM
testnet               192.0.2.0
EOM

check "getent.ldap networks | grep testnet" << EOM
testnet               192.0.2.0
EOM

###########################################################################

echo "test_ldapcmds.sh: testing passwd..."

check "getent.ldap passwd ecolden | sed 's/:[x*]:/:x:/'" << EOM
ecolden:x:5972:1000:Estelle Colden:/home/ecolden:/bin/bash
EOM

check "getent.ldap passwd arthur | sed 's/:[x*]:/:x:/'" << EOM
arthur:x:1000:100:Arthur de Jong:/home/arthur:/bin/bash
EOM

# check username with different case
check "getent.ldap passwd ARTHUR" << EOM
EOM

check "getent.ldap passwd 4089 | sed 's/:[x*]:/:x:/'" << EOM
jguzzetta:x:4089:1000:Josephine Guzzetta:/home/jguzzetta:/bin/bash
EOM

# count the number of passwd entries in the 4000-5999 range
check "getent.ldap passwd | grep -c ':[x*]:[45][0-9][0-9][0-9]:'" << EOM
2000
EOM

###########################################################################

echo "test_ldapcmds.sh: testing protocols..."

check "getent.ldap protocols protfoo" << EOM
protfoo               253 protfooalias
EOM

check "getent.ldap protocols protfooalias" << EOM
protfoo               253 protfooalias
EOM

# check protocol with different case
check "getent.ldap protocols PROTFOO" << EOM
EOM

# test protocol alias with different case
check "getent.ldap protocols PROTFOOALIAS" << EOM
EOM

check "getent.ldap protocols 253" << EOM
protfoo               253 protfooalias
EOM

check "getent.ldap protocols | grep protfoo" << EOM
protfoo               253 protfooalias
EOM

###########################################################################

echo "test_ldapcmds.sh: testing rpc..."

check "getent.ldap rpc rpcfoo" << EOM
rpcfoo          160002  rpcfooalias
EOM

check "getent.ldap rpc rpcfooalias" << EOM
rpcfoo          160002  rpcfooalias
EOM

# test rpc name with different case
check "getent.ldap rpc RPCFOO" << EOM
EOM

check "getent.ldap rpc 160002" << EOM
rpcfoo          160002  rpcfooalias
EOM

check "getent.ldap rpc | grep rpcfoo" << EOM
rpcfoo          160002  rpcfooalias
EOM

###########################################################################

echo "test_ldapcmds.sh: testing services..."

check "getent.ldap services foosrv" << EOM
foosrv                15349/tcp
EOM

check "getent.ldap services foosrv/tcp" << EOM
foosrv                15349/tcp
EOM

check "getent.ldap services foosrv/udp" << EOM
EOM

# check with different case
check "getent.ldap services FOOSRV" << EOM
EOM

# check protocol name case sensitivity (TCP is commonly an alias)
check "getent.ldap services foosrv/tCp" << EOM
EOM

check "getent.ldap services 15349/tcp" << EOM
foosrv                15349/tcp
EOM

check "getent.ldap services 15349/udp" << EOM
EOM

check "getent.ldap services barsrv | sort" << EOM
barsrv                15350/tcp
barsrv                15350/udp
EOM

check "getent.ldap services barsrv/tcp" << EOM
barsrv                15350/tcp
EOM

check "getent.ldap services barsrv/udp" << EOM
barsrv                15350/udp
EOM

check "getent.ldap services | egrep '(foo|bar)srv' | sort" << EOM
barsrv                15350/tcp
barsrv                15350/udp
foosrv                15349/tcp
EOM

check "getent.ldap services sssin" << EOM
sssin                 5000/tcp SSSIN
EOM

check "getent.ldap services SSSIN" << EOM
sssin                 5000/tcp SSSIN
EOM

check "getent.ldap services | sort" << EOM
barsrv                15350/tcp
barsrv                15350/udp
foosrv                15349/tcp
sssin                 5000/tcp SSSIN
EOM

###########################################################################

echo "test_ldapcmds.sh: testing shadow..."

# function to remove the password field from output
rmpasswd() {
  sed 's/^\([^:]*\):[^:]*:/\1:*:/'
}

check "getent.ldap shadow ecordas | rmpasswd" << EOM
ecordas:*::::7:2::0
EOM

check "getent.ldap shadow adishaw | rmpasswd" << EOM
adishaw:*:12302:::7:2::0
EOM

# check case-sensitivity
check "getent.ldap shadow ADISHAW" << EOM
EOM

# check if the names of users match between passwd and shadow
getent_ldap passwd | sed 's/:.*//' | sort | \
  check "getent.ldap shadow | sed 's/:.*//' | sort"

###########################################################################
# determine the result

if [ $FAIL -eq 0 ]
then
  echo "test_ldapcmds.sh: all tests passed"
  exit 0
else
  echo "test_ldapcmds.sh: $FAIL TESTS FAILED"
  exit 1
fi
