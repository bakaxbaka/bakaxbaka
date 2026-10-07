$(
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
    Metamath source file for logic, set theory, numbers, and Hilbert space
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#

set.mm - Version of 25-Mar-2005

                             PUBLIC DOMAIN

This file (specifically, the version of this file with the above date)
is placed in the public domain per the Creative Commons Public Domain
Dedication. http://creativecommons.org/licenses/publicdomain/

Norman Megill - email: nm(at)alum(dot)mit(dot)edu

=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
                          Recent label changes
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

This is part of an ongoing project to improve naming consistency.  If
you are using set.mm as the base for your project, you should review the
following changes before updating to this version of set.mm.  If you
want to create an automated script, you can make can make global
substitutions into your database by processing the ones without "Notes"
in _reverse_ order and matching a space or beginning-of-line before the
label and a space or end-of-line after the label.  The ones with "Notes"
should be processed manually.  If you have suggestions for better names
let me know.

Date       Old       New         Notes

18-Mar-05  reim0     reim0b
18-Mar-05  rere      rereb
18-Mar-05  cjre      cjreb
18-Mar-05  negre     negreb
11-Mar-05  frsuc     frsuct
10-Mar-05  nn0addge2 [--same--]  Generalized 1st hyp from NN0 to RR
10-Mar-05  nn0addge1 [--same--]  Generalized 1st hyp from NN0 to RR
 5-Mar-05  chv       chvarv
 5-Mar-05  chv2      chvar
 4-Mar-05  divdistr  divdir
 4-Mar-05  divdistrz divdirz
 4-Mar-05  divge0t   [--same--]  conjoined the two left-most antecedents
 4-Mar-05  divgt0t   [--same--]  conjoined the two left-most antecedents
 4-Mar-05  absgt0t   [--same--]  changed  -. A = 0  to  A =/= 0
 4-Mar-05  absgt0    [--same--]  changed  -. A = 0  to  A =/= 0
 4-Mar-05  climuni   [--same--]  eliminated F e. V hypothesis
 4-Mar-05  climunii  [--same--]  eliminated F e. V hypothesis
 4-Mar-05  climconv  [--same--]  eliminated F e. V hypothesis
 4-Mar-05  climseq   [--same--]  eliminated F e. V hypothesis
 4-Mar-05  clim      [--same--]  eliminated F e. V hypothesis
24-Feb-05  absidt    [--same--]  conjoined the two left-most antecedents
27-Feb-05  del34     ---         obsolete; use dral1 instead
27-Feb-05  del35     ---         obsolete; use dral1 instead
27-Feb-05  del34b    dral1
27-Feb-05  del36     ---         obsolete; use dral2 instead
27-Feb-05  del40     ---         obsolete; use drex1 instead
27-Feb-05  del41     ---         obsolete; use drex1 instead
27-Feb-05  del42     ---         obsolete; use drex2 instead
27-Feb-05  del43     ---         obsolete; use drsb1 instead
27-Feb-05  del43b    drsb1
27-Feb-05  del44     ---         obsolete; use drsb2 instead
27-Feb-05  del45     ---         obsolete; use drsb2 instead
27-Feb-05  ddelimf2  dvelimf2
27-Feb-05  ddelimf   dvelimf
27-Feb-05  ddelimdf  dvelimdf
27-Feb-05  ddelim    dvelim
27-Feb-05  ddeeq1    dveeq1
27-Feb-05  ddeeq2    dveeq2
27-Feb-05  ddeel1    dveel1
27-Feb-05  ddeel2    dveel2
24-Feb-05  bi3ord    3orbi123d
24-Feb-05  im3ord    3orim123d
24-Feb-05  bi3or     3orbi123i
24-Feb-05  bi3an     3anbi123i
24-Feb-05  bi3and    3anbi123d
24-Feb-05  im3an     3anim123i
24-Feb-05  divdistrt divdirt
24-Feb-05  ltdivt    [--same--]  conjoined the two left-most antecedents
24-Feb-05  ledivt    [--same--]  conjoined the two left-most antecedents
24-Feb-05  ltmuldivt [--same--]  conjoined the two left-most antecedents
24-Feb-05  ltdivmult [--same--]  conjoined the two left-most antecedents
24-Feb-05  ltmuldiv2t [--same--]  conjoined the two left-most antecedents
24-Feb-05  gt0ne0t   [--same--]  conjoined the two left-most antecedents
24-Feb-05  ltrect    [--same--]  conjoined the two left-most antecedents
24-Feb-05  recgt0t   [--same--]  conjoined the two left-most antecedents
24-Feb-05  lerect    [--same--]  conjoined the two left-most antecedents
21-Feb-05  nn0ge0i   nn0ge0
21-Feb-05  rdgzer    rdg0
21-Feb-05  rdgzert   rdg0t
21-Feb-05  frzer     fr0t
21-Feb-05  mulzer1   mul01
21-Feb-05  mulzer2   mul02
21-Feb-05  mulzer1t  mul01t
21-Feb-05  mulzer2t  mul02t
21-Feb-05  divzer    div0
21-Feb-05  ax-hvzercl ax-hv0cl
21-Feb-05  ax-hvmulzer ax-hvmul0
21-Feb-05  hizer1t   hi01t
21-Feb-05  hizer2t   hi02t
19-Feb-05  ax0re     0re
13-Feb-05  cardcard  cardidm
13-Feb-05  exp2t     sqvalt
13-Feb-05  uzind2    uzind3
 6-Feb-05  climcn    ---         Obsolete; use climcl
 5-Feb-05  ---       ---         We will adopt "equ" (vs. old "eq") for
                                 set variable equality and "eq" (vs. old
                                 "cleq") for class equality.  (Remember it
                                 is important to do these in REVERSE order
                                 below!)
 5-Feb-05  cleqri    eqri
 5-Feb-05  cleqrd    eqrd
 5-Feb-05  cleqid    eqid
 5-Feb-05  cleqcom   eqcom
 5-Feb-05  cleqcomi  eqcomi
 5-Feb-05  cleqcomd  eqcomd
 5-Feb-05  cleq1     eqeq1
 5-Feb-05  cleq2     eqeq2
 5-Feb-05  cleq1i    eqeq1i
 5-Feb-05  cleq2i    eqeq2i
 5-Feb-05  cleq1d    eqeq1d
 5-Feb-05  cleq2d    eqeq2d
 5-Feb-05  cleq12    eqeq12
 5-Feb-05  cleq12i   eqeq12i
 5-Feb-05  cleq12d   eqeq12d
 5-Feb-05  cleqan12d eqeqan12d
 5-Feb-05  cleqan12rd eqeqan12rd
 5-Feb-05  cleqtr    eqtrt
 5-Feb-05  cleq2tr   eq2tr
 5-Feb-05  cleqab    eqab
 5-Feb-05  cleqabi   eqabi
 5-Feb-05  cleqabr   eqabr
 5-Feb-05  cleqabd   eqabd
 5-Feb-05  cleqabri  eqabri
 5-Feb-05  cleq2ab   eq2ab
 5-Feb-05  cleqrabi  eqrabi
 5-Feb-05  clneq     nelneq
 5-Feb-05  clneq2    nelneq2
 5-Feb-05  sbeq2     equsb2
 5-Feb-05  sbeq1     equsb1
 5-Feb-05  eqvin.l2  ---           obsolete; use equvin instead
 5-Feb-05  eqvin     equvin
 5-Feb-05  eqvin.l1  equvini
 5-Feb-05  eqsal     equsal
 5-Feb-05  eqsex     equsex
 5-Feb-05  eqs5      equs5
 5-Feb-05  eqs4      equs4
 5-Feb-05  eqs3      equs3
 5-Feb-05  eqs2      equs2
 5-Feb-05  eqs1      equs1
 5-Feb-05  eq6s      hbnaes
 5-Feb-05  eq6       hbnae
 5-Feb-05  eq5s      hbaes
 5-Feb-05  eq5       hbae
 5-Feb-05  eq4ds     nalequcoms
 5-Feb-05  eq4s      alequcoms
 5-Feb-05  eq4       alequcom
 5-Feb-05  a14b      elequ2
 5-Feb-05  a13b      elequ1
 5-Feb-05  eqt2b     equequ2
 5-Feb-05  a8b       equequ1
 5-Feb-05  eqt       equtr
 5-Feb-05  eqt2      equtrr
 5-Feb-05  eqan      equtr2
 5-Feb-05  eqcom     equcomi
 5-Feb-05  eqcomb    equcom
 5-Feb-05  eqcoms    equcoms
 5-Feb-05  eqid      equid
 3-Feb-05  sb5f1     sb6rf
21-Jan-05  mulcanxx  mulcant2
21-Jan-05  mulcant2  mulcant
21-Jan-05  mulcant   mulcanxx
10-Jan-05  add41r3   add42
10-Jan-05  caopr41r3 caopr42
10-Jan-05  an41r3s   an42s
10-Jan-05  an41r3    an42
 8-Jan-05  im2an     anim12i
 8-Jan-05  imran     anim1i
 8-Jan-05  imlan     anim2i
 8-Jan-05  im2or     orim12i
 8-Jan-05  imror     orim1i
 8-Jan-05  imlor     orim2i
 8-Jan-05  im2and    anim12d
 8-Jan-05  imrand    anim1d
 8-Jan-05  imland    anim2d
 8-Jan-05  im2ord    orim12d
 8-Jan-05  imrord    orim1d
 8-Jan-05  imlord    orim2d
 8-Jan-05  ---       ---         The bixxx series was changed to be analogous
                                 to the xxeqx series e.g. uneq12d.
 8-Jan-05  bi2and    anbi12d
 8-Jan-05  birand    anbi1d
 8-Jan-05  biland    anbi2d
 8-Jan-05  bi2imd    imbi12d
 8-Jan-05  birimd    imbi1d
 8-Jan-05  bilimd    imbi2d
 8-Jan-05  bi2ord    orbi12d
 8-Jan-05  birord    orbi1d
 8-Jan-05  bilord    orbi2d
 8-Jan-05  bi2bid    bibi12d
 8-Jan-05  birbid    bibi1d
 8-Jan-05  bilbid    bibi2d
 8-Jan-05  binegd    negbid
 8-Jan-05  bi2an     anbi12i
 8-Jan-05  biran     anbi1i
 8-Jan-05  bilan     anbi2i
 8-Jan-05  bi2im     imbi12i
 8-Jan-05  birim     imbi1i
 8-Jan-05  bilim     imbi2i
 8-Jan-05  bi2or     orbi12i
 8-Jan-05  biror     orbi1i
 8-Jan-05  bilor     orbi2i
 8-Jan-05  bi2bi     bibi12i
 8-Jan-05  birbi     bibi1i
 8-Jan-05  bilbi     bibi2i
 8-Jan-05  bineg     negbii
 3-Jan-05  pm5.41    imdi
 1-Jan-05  iundif    iundif2
 1-Jan-05  iindif    iindif2
 1-Jan-05  iunin     iunin2
 1-Jan-05  iinin     iinin2
 1-Jan-05  sylan13br sylancbr
 1-Jan-05  sylan13b  sylancb
 1-Jan-05  sylan13   sylanc
 1-Jan-05  syl13     sylc
26-Dec-04  0ne1o     ---         obsolete; use 1ne0
19-Dec-04  sbequ6    [--same--]  swapped biconditional order
19-Dec-04  sbequ5    [--same--]  swapped biconditional order
15-Dec-04  syl2and   syl2ani
15-Dec-04  sylan2d   sylan2i
15-Dec-04  syland    sylani
12-Dec-04  nnordex   nnaordex
12-Dec-04  nnwordex  nnawordex
12-Dec-04  mpand     mpdan
12-Dec-04  ontr      ontr1
 6-Dec-04  on0eqel   on0eqelt
30-Nov-04  exp2      sqvalt
30-Nov-04  1exp      1expt
30-Nov-04  0exp      0expt
30-Nov-04  exp1      exp1t
30-Nov-04  expp1     expp1t
18-Nov-04  divrclz   redivclz
18-Nov-04  divrclt   redivclt
18-Nov-04  subrclt   resubclt
18-Nov-04  negrclt   renegclt
18-Nov-04  mulrclt   remulclt
18-Nov-04  divrcl    redivcl
18-Nov-04  subrcl    resubcl
18-Nov-04  negrcl    renegcl
18-Nov-04  mulrcl    remulcl
18-Nov-04  addrcl    readdcl
18-Nov-04  ltdivmul  ---         obsolete; use ltmuldiv instead
18-Nov-04  ltdivmult ---         obsolete; use ltmuldivt instead (note: there
                                 is a new ltdivmult that is unrelated)
18-Nov-04  distr2t   adddirt
18-Nov-04  distr2    adddir
18-Nov-04  distr     adddi
18-Nov-04  subdistr  subdir
17-Nov-04  nnrect    nnrecgt0t
17-Nov-04  posdif    [--same--]  swapped biconditional and variable order
15-Nov-04  negdistt3 negdi3t
15-Nov-04  negdistt2 negdi2t
15-Nov-04  negdistt  negdit
15-Nov-04  negdist3  negdi3
15-Nov-04  negdist2  negdi2
11-Nov-04  reuunis   reuuni2
11-Nov-04  reuuni    reuuni1
 9-Nov-04  zlelt1    zleltp1t
 9-Nov-04  zltle1    zltp1let
 7-Sep-04  arch      [--same--]  removed quantifier, changed set var. to class
 2-Nov-04  dfom2     dfom3
 2-Nov-04  dfom3     dfom4
29-Oct-04  df-ded    df-if
29-Oct-04  dedeq1    ifeq1
29-Oct-04  dedeq2    ifeq2OLD
29-Oct-04  dedeq12   ifeq12
29-Oct-04  dedbi     ifbi
29-Oct-04  dedlem1   iftrue
29-Oct-04  dedlem2   iffalse
29-Oct-04  dedex     ifex
29-Oct-04  cded      cif         changed math symbol "ded" to "if" everywhere!
20-Oct-04  oprabex   oprabex2
14-Oct-04  nn0lelt1  nn0leltp1t
14-Oct-04  nn0ltle1  nn0ltp1let
14-Oct-04  nnlelt1   nnleltp1t
14-Oct-04  nnltle1   nnltp1let
14-Oct-04  rnoel3    rabn0
14-Oct-04  noel3     abn0
14-Oct-04  noel2     n0i
14-Oct-04  peano5c   peano5nn
14-Oct-04  peano2c   peano2nn
12-Oct-04  supeu     supeui
12-Oct-04  supcl     supcli
12-Oct-04  supub     supubi
12-Oct-04  suplub    suplubi
12-Oct-04  supnub    supnubi
12-Oct-04  suprcl    suprcli
12-Oct-04  suprub    suprubi
12-Oct-04  pm4.12    bicon2
12-Oct-04  bicon4    bicon4i
12-Oct-04  bicon2    bicon2i
12-Oct-04  bicon1    bicon1i
12-Oct-04  pm2.11    exmid
11-Oct-04  sbf1      ---         obsolete; use sbf instead
11-Oct-04  ceqsexg   ceqex
 9-Oct-04  fvco2     fvco3
 8-Oct-04  indif0    difdisj
 8-Oct-04  biopab    biopabi
 8-Oct-04  bioprab   bioprabi
 7-Oct-04  ssii      sselii
 6-Oct-04  op2nd     op2ndb
 6-Oct-04  op1st     op1stb
 3-Oct-04  ind       nnind
 3-Oct-04  sylan5    sylan2
 3-Oct-04  sylan5b   sylan2b
 3-Oct-04  sylan5br  sylan2br
 3-Oct-04  sylan5d   sylan2i
 3-Oct-04  zind      uzind
30-Sep-04  fvop      funopfv
30-Sep-04  funopfv   funfvopi
30-Sep-04  pm4.21    bicom
30-Sep-04  bicom     bicomi
30-Sep-04  entr      entri
30-Sep-04  sstr2xxx  sstr
30-Sep-04  sstr      sstr2
30-Sep-04  sstr2     sstr2xxx
29-Sep-04  xp0xxx    xp0r
29-Sep-04  xp0r      xp0
29-Sep-04  xp0       xp0xxx
28-Sep-04  xpdom2    xpdom3
28-Sep-04  xpdom     xpdom2      changed variable names
26-Sep-04  xpindi    inxp
26-Sep-04  xpun1     xpundi
26-Sep-04  xpun2     xpundir
25-Sep-04  entr      entrt
23-Sep-04  ssfnres   ---         obsolete; use fnssres instead
23-Sep-04  resun     resundi
21-Sep-04  f11       [--same--]  changed o.p. membership to binary relation
21-Sep-04  unisuc    [--same--]  swapped arguments of = sign
21-Sep-04  onunisuc  [--same--]  swapped arguments of = sign
21-Sep-04  ssundif   [--same--]  swapped arguments of = sign
21-Sep-04  ssequn2   [--same--]  swapped arguments of = sign
21-Sep-04  sseqin2   [--same--]  swapped arguments of = sign
21-Sep-04  onelun    [--same--]  swapped arguments of = sign
21-Sep-04  dfss4     [--same--]  swapped arguments of = sign
21-Sep-04  ordunisuc ordunisssuc
21-Sep-04  ssfun     funss
15-Sep-04  19.6      alex
15-Sep-04  alex      alexeq
15-Sep-04  19.11     excom
15-Sep-04  19.11a    excomim
15-Sep-04  19.5      alcom
15-Sep-04  19.7      alnex
15-Sep-04  19.14     exnal
15-Sep-04  alnex     alinexa
15-Sep-04  exnal     exanali
15-Sep-04  dmsn      dmsnop
15-Sep-04  rnsn      rnsnop
13-Sep-04  ppnull    pwpw0
13-Sep-04  pwnull    pw0
13-Sep-04  zfnull2   zfnul
13-Sep-04  nullpss   0pss
13-Sep-04  nullss    0ss
13-Sep-04  nulleq    eq0
13-Sep-04  nnull     n0
13-Sep-04  nnullf    n0f
13-Sep-04  xpdisj    xpsndisj
13-Sep-04  subdist   subdi
13-Sep-04  ecoprdist ecoprdi
13-Sep-04  negdist   negdi
13-Sep-04  nndist    nndi
13-Sep-04  xpindist  inxp
11-Sep-04  ssd       sseld
11-Sep-04  ssi       sseli
11-Sep-04  vtoclab   elab2
11-Sep-04  vtoclabg  elab2g
11-Sep-04  elab2g    elab3g
 6-Sep-04  comm      com12
 4-Sep-04  opabval   fvopab3
 4-Sep-04  opabvalig fvopab3ig
 4-Sep-04  opabval2g fvopab4g
 4-Sep-04  opabval2  fvopab4
 3-Sep-04  undif2    difun2
 3-Sep-04  undif3    ssundifOLD
 1-Sep-04  dedlem2   [--same--]  swapped arguments of = sign
 1-Sep-04  dedlem1   [--same--]  swapped arguments of = sign
31-Aug-04  pm2.16d   con3d
31-Aug-04  pm2.03d   con2d
31-Aug-04  pm2.15d   con1d
31-Aug-04  pm2.16    con3
31-Aug-04  pm2.03    con2
31-Aug-04  pm2.15    con1
31-Aug-04  con3      con3i
31-Aug-04  con2      con2i
31-Aug-04  con1      con1i
29-Aug-04  oprabelrn elrnoprab
27-Aug-04  ssequn1   [--same--]  swapped arguments of = sign
27-Aug-04  df-ss     dfss
27-Aug-04  imdistanb ---         obsolete; use imdistan
27-Aug-04  imdistan  [--same--]  now includes converse
17-Aug-04  difun2    [--same--]  swapped arguments of = sign
17-Aug-04  undif1    [--same--]  swapped arguments of = sign and union
17-Aug-04  difin     [--same--]  swapped arguments of = sign
17-Aug-04  unindistr undir
17-Aug-04  unindist  undi
17-Aug-04  inundistr indir
17-Aug-04  inundist  indi
17-Aug-04  indist    inindi
16-Aug-04  ss2un     unss12      order of variables changed
15-Aug-04  funmo,dffunmof,dffunmo
                     [--same--]  ordered pair membership -> binary relation
15-Aug-04  dfrel2    [--same--]  swapped arguments of = sign
12-Aug-04  unxp      xpundir
11-Aug-04  elima2    elima3
11-Aug-04  reluni    [--same--]  restricted quantifier and added converse
 9-Aug-04  imun      imaun
 3-Aug-04  1id       om1
 3-Aug-04  oalim     [--same--]  conjoined antecedents; now uses indexed union
 3-Aug-04  divdiv23  divdiv23z
 3-Aug-04  divdiv23i divdiv23
 2-Aug-04  divrec,divrecz [--same--] swapped A and B
 2-Aug-04  zq        zqt
 2-Aug-04  qre       qret
 1-Aug-04  mulcant  [--same--]  swapped conjunct in antecedent
 1-Aug-04  axrecex,axrrecex,divclt,divcan1t,divcan2t,recidt,divdistrt,divrclt
                     [--same--]  conjoined the two left-most antecedents
 1-Aug-04  peano1c   1nn
 1-Aug-04  1nn       1onn
28-Jul-04  sbco0     sbid2
28-Jul-04  sbid2     sbid2v
26-Jul-04  cardonval oncardval
15-Jun-04  ssin      [--same--]  swapped biconditional order
15-Jun-04  unss      [--same--]  swapped biconditional order
11-Jun-04  dfun2     df-un
11-Jun-04  df-un     dfun2
11-Jun-04  dfin2     df-in
11-Jun-04  df-in     dfin2
 3-Jun-04  ssintss   intss
 3-Jun-04  intss     intss1
30-May-04  r1clos    r1pwcl      now uses antecedent instead of hypothesis
30-May-04  r1powt    r1pw
28-May-04  sqvalt    ---         obsolete; use exp2
28-May-04  expntwo   exp2
28-May-04  expnone   ---         obsolete; use expp1t
28-May-04  expnsuc   ---         obsolete; use expp1t
28-May-04  expnzer   ---         obsolete; exp^0 no longer defined; just use 1
26-May-04  ontrt     ---         obsolete; use onelon instead
26-May-04  ddelim*   [--same--]  (*=wildcard) changed order of hypotheses
21-May-04  fvcnvb    f1ocnvfvb
21-May-04  fvcnv     f1ocnvfv
21-May-04  sbcb      sbcbi       now uses antecedent instead of hypothesis
21-May-04  sbci      sbcim
21-May-04  sbb       sbbi
21-May-04  sbo       sbor
21-May-04  sbi       sbim
21-May-04  sbim      sbimi
21-May-04  sba       sban
21-May-04  fvelrn    [--same--]  changed to restricted quantifier
>8-Feb-04  zfpowb    pwexb
>8-Feb-04  zfpowcl   pwex
>8-Feb-04  zfnull    0ex
>8-Feb-04  limelon   [--same--]  changed first -> to /\ in antecedent


=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
                              Bibliography
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Bibliographical references are made by bracketing an identifer in a
theorem's comment, such as [RussellWhitehead].  These refer to HTML tags
on the following web pages:

  Logic and set theory - see http://us.metamath.org/mpegif/mmset.html#bib
  Hilbert space - see http://us.metamath.org/mpegif/mmhil.html#ref


=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
     Quick "How To" use this file (under Windows 95/98/NT/2K/XP)
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

1. Download the program metamath.exe per the instructions on the
   Metamath home page (http://metamath.org) and put it in the same
   directory as this file (set.mm).
2. In Windows Explorer, double-click on metamath.exe.
3. Type "read set.mm" and press Enter.
4. Type "help" for a list of help topics, and "help demo" for some
   command examples.


=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
                       Metamath syntax summary
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

The HELP LANGUAGE command in the Metamath program will give you a quick
overview of Metamath.  Syntax summary:

          $c ... $. - Constant declaration
          $v ... $. - Variable declaration
          $d ... $. - Disjoint (distinct) variable restriction
  <label> $f ... $. - "Floating" (variable-type) hypothesis
  <label> $e ... $. - "Essential" (logical) hypothesis (i.e. theorem
                      assumption)
  <label> $a ... $. - Axiom or definition or syntax construction
  <label> $p ... $= ... $. - Theorem and its proof
          ${ ... $} - Block for scoping above statements (except $a, $p
                      which are forever active)
$)        $( ... $) $( - Comments (may not be nested); see HELP LANGUAGE
                         for markup features
          $[ ... $] - Include file

The above tokens (i.e. those beginning with "$") are the ONLY primitives
built into the Metamath language.  The only 'logic' Metamath uses in its
proof verification algorithm is the substitution of expressions for
variables while checking for distinct variable violations.  EVERYTHING
ELSE, including the axioms for logic, is defined in this database file.

Here is some more detail about the syntax.  A <token> may not contain
the "$" character but may contain any other non-whitespace printable
character.  A <label> may contain only alphanumeric characters and the
characters ".-_".  Tokens and labels are case-sensitive.

          $c <tokenlist> $. <tokenlist> is a (whitespace-separated) list of
                            distinct tokens unused in current scope.
          $v <tokenlist> $. <tokenlist> is a (whitespace-separated) list of
                            distinct tokens unused in current scope.
          $d <tokenlist> $. <tokenlist> is a (whitespace-separated) list of
                            distinct tokens previously declared with $v in
                            current scope.  It means that substitutions into
                            these tokens may not have variables in common.
  <label> $f <tokenlist> $. <tokenlist> is a list of 2 tokens, the first of
                            which must be previously declared with $c
                            in the current scope.
  <label> $e <tokenlist> $. <tokenlist> is a list of 2 or more tokens, the
                            first of which must be previously declared with $c
                            in the current scope.
  <label> $a <tokenlist> $. <tokenlist> is a list of 2 or more tokens, the
                            first of which must be previously declared with $c
                            in the current scope.
  <label> $p <tokenlist> $= <proof> $. <tokenlist> is a list of 2 or more
                            tokens, the first of which must be previously
                            declared with $c in the current scope.  <proof> is
                            either a whitespace-delimited sequence of previous
                            labels (created by SAVE PROOF <label> /NORMAL) or a
                            compressed proof (created by SAVE PROOF <label>
                            /COMPRESSED).  After using SAVE PROOF, use
                            WRITE SOURCE to save the database file to disk.
          ${ ... $} - Block for scoping the above statements (except $a, $p
                      which are forever active)
$)        $( <any text> $) $( Comment.  Note: <any text> may not contain
                             adjacent "$" and ")" characters.
          $[ <filename> $]   Insert contents of <filename> at this point.
                             If <filename> is current file or has been already
                             been inserted, it will not be inserted again.

Inside of comments, it is recommended that labels be preceded with a tilde (~)
and math symbol tokens be enclosed in grave accents (` `).  This way the
LaTeX and HTML rendition of comments will be accurate, and (future) tools
to globally change labels and math symbols will also change them in comments.
Note that `` inside of grave accents is interpreted as a single ` .
See HELP LANGUAGE for other markup features in comments.

The proofs in this file are in "compressed" format for storage efficiency. The
Metamath program reads the compressed format directly.  This format is
described in an Appendix of the Metamath book.  It is not intended to be
read by humans.  For viewing proofs you should use the various SHOW PROOF
commands described in the Metamath book (or the on-line HELP).


=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
                           Other notes
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

1. It is recommended that you be familiar with chapters 2 and 4 of the
'Metamath' book to understand the Metamath language.  Chapters 2, 3 and
5 explain how to use the program.  Chapter 3 gives you an informal
overview of what this source file is all about.  Appendix A shows you
the standard mathematical symbols corresponding to the ASCII tokens in
this file.

The ASCII tokens may seem cryptic at first, even if you are familiar with set
theory, but a review of the definition summary in Chapter 3 should quickly
enable you to see the correspondence to standard mathematical notation. To
easily find the definition of a token, search for the first occurrences of the
token surrounded by spaces.  Some odd-looking ones include "-." for "not", and
"(_" for "is a subset of".  (HELP TEX tells you how to obtain a LaTeX
output to see the real mathematical symbols.)  Let me know if you have
better suggestions for naming ASCII tokens.

2. Logic and set theory provide a foundation for all of mathematics.  To learn
about them, you should study this source file in conjunction with one or more
of the references listed below.  The textbooks provide a motivation for what we
are doing, whereas Metamath lets you see in detail all hidden and implicit
steps. Most standard theorems are accompanied by citations.  Some closely
followed texts include the following:

  Axioms of propositional calculus - [Margaris].
  Axioms of predicate calculus - [Megill] (System S3' in the article
      referenced).
  Theorems of propositional calculus - [WhiteheadRussell].
  Theorems of pure predicate calculus - [Margaris].
  Theorems of equality and substitution - [Monk2], [Tarski], [Megill].
  Axioms of set theory - [BellMachover].
  Development of set theory - [TakeutiZaring].  (The first part of [Quine]
      has a good explanation of the powerful device of "virtual" or
      class abstractions, which is essential to our development.)
  Construction of real and complex numbers - [Gleason]
  Theorems about real numbers - [Apostol]

3. Convention:  All $a statements starting with "|-" have labels
starting with "ax-" (axioms) or "df-" (definitions).  "ax-" corresponds
to what is traditionally called an axiom.  "df-" introduces new symbols
or a new relationship among symbols that can be eliminated; they always
extend the definition of a wff or class.  Metamath blindly treats $a
statements as new facts but does not try to justify them; their
justification is the job of mathematicians and philosophers.  Generally
our philosophy is to make definitions easy to eliminate by simple symbol
substitutions.

4. Our method of definition, the axioms for predicate calculus, and the
development of substitution are somewhat different from those found in
standard texts.  The axioms were designed for direct derivation of
standard results without excessive use of metatheorems.  (See Theorem
9.7 of [Megill] for a rigorous justification.)  Typically we are
minimalist when introducing new definitions; they are introduced only
when a clear advantage becomes apparent for reducing the number of
symbols, shortening proofs, etc.  We generally avoid the introduction of
excessive definitions because each one requires associated theorems and
additional elimination steps in proofs.

5. For the most part, the notation conforms to modern conventions, with
variations due to our choice of the axiom system or to make proofs
shorter.  Listed below are some important conventions and how they
correspond to textbook language.  The notation is usually explained in
more detail when first introduced.

  Typically, Greek letters (ph = phi, ps = psi, ch = chi, etc.) are used for
      propositional (wff) variables; x,y,z,... for individual (i.e. set)
      variables; and A,B,C,... for class variables.
  "|-", meaning "It is provable that," is the first token of all assertions
      and hypotheses that aren't syntax constructions.  This is a standard
      convention in logic.  For us, it also prevents any ambiguity with
      statements that are syntax constructions, such as "wff -. ph".
  "$e |- ( ph -> A. x ph ) $." should be read "Assume variable x is
      (effectively) not free in wff phi."  Literally, this says "Assume it is
      provable that phi implies for all x phi."
  "|- ( -. A. x x = y -> ..." should be read "If x and y are distinct
      variables, then..."  This antecedent provides us with a technical
      device (called a "distinctor" in [Megill]) to avoid the need for the
      $d statement early in our development of predicate calculus, permitting
      unrestricted substitituions as conceptually simple as those in
      propositional calculus.  However, the $d eventually becomes a
      requirement, and after that this device is rarely used.
  "[ y / x ] ph" should be read "the wff that results when y is properly
      substituted for x in ph."
  "$d x y $." should be read "Assume x and y are distinct variables."
  "$d x ph $." should be read "Assume x does not occur in phi $."  Sometimes
      a theorem is proved with "$e |- ( ph -> A. x ph ) $." in place of
      "$d x ph $." when a more general result is desired; ~ ax-17 can be used
      to derive the $d version.  For an example of how to get from the $d
      version back to the $e version, see the proof of ~ euf from ~ df-eu .
  "$d x A $." should be read "Assume x is not a variable occurring in class
      A."
  "$d x A $.  $d x ps $.  $e |- ( x = A -> ( ph <-> ps ) ) $." is often used
      instead of explicit substitution, meaning "Assume psi results from the
      substitution of A for x in phi".
  "$e |- A e. V $." should be read "Assume class A is a set (i.e. exists)."
      This is a convenient convention used by [Quine].
  "$d x y $.  $e |- y e. A -> A. x y e. A $." should be read "Assume x is
      (effectively) not a free variable in class A."
  "`' R" should be read "converse of (relation) R" and is the same as
      the more standard notation R^{-1}.
  "( f ` x )" should be read "the value of function f at x" and is the same
      as the more familiar f(x).
  The Deduction Theorem of standard logic is never used.  Instead, in
      set theory we use other tricks to make a $e hypothesis become
      an antecedent.  See the comment for theorem dedth below.


A note for anyone attempting to find shorter proofs
---------------------------------------------------

I always like shorter proofs, and any shorter proof I accept will be
acknowledged and put into the next version of the Metamath site.

I will automatically accept shorter proofs conforming to these
guidelines:  (1) only existing, unmodified theorems in the database are
used (the order of theorems may be changed though), (2) the number of
characters in the compressed proof is less than before, (3) the last
step number in SHOW PROOF when the proof is compressed is less than
before, (4) the number of steps in the HTML file (SHOW STATEMENT xxx /
HTML) is less than before, (5) the size of the HTML file is less than
before, (6) no additional axioms are used, and (7) none of the special
cases listed below apply.  If not all of these are the case I may still
accept the proof on a case-by-case basis.

There are several theorems that purposely do not have shortest proofs:

The proof of id1 , ax9a , ax15 , snex , sbth , ordon , ltso and several
other theorems (in particular ones avoiding ax-reg and ax-ac ) could be
made shorter but are longer to illustrate specific points or to avoid
specific axioms.

The following proofs should not be MINIMIZE_WITH'ed in the Proof
Assistant, since they are for illustrative purposes or they involve areas
I want to rework in the future.

   " id1 " using " a2i "
   " id1 " using " id "
   " con3th " using " con3 "
   " meredith " through " ax3 " using anything
   " ax9a " using " ax-9 "
   " ax15 " using " ax-15 "
   " dvelimf2 " using " dvelimf "
   " nnm0r " or anything else now using " om0 ", using " om0x "
   " omex " using " inf3 "
   " pjpj " using " pjpj0 "
   " pjoml " using " omls "
   " pjococ " using " omlsi "
   " pjococ " using " ococ "
   " pjpjtht " using " pjtht "
   " pjpjth " using " pjth "

Also, in set theory don't use equequ1 , equequ2 , elequ1 , elequ2 (use set theory
versions eqeq1 , eqeq2 , eleq1 , eleq2 instead).
Use om0 instead of om0x .
Don't use eirr if efrirr , ordeirr , or oneirr can be used (to avoid the
Axiom of Regularity when it is not needed).

$)

$(
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
                           Propositional calculus
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
$)

  $( Declare the primitive constant symbols for propositional calculus. $)
  $c ( $.  $( Left parenthesis $)
  $c ) $.  $( Right parenthesis $)
  $c -> $. $( Right arrow (read:  'implies') $)
  $c -. $. $( Right handle (read:  'not') $)
  $c wff $. $( Well-formed formula symbol (read:  'the following symbol
               sequence is a wff') $)
  $c |- $. $( Turnstile (read:  'the following symbol sequence is provable' or
              'a proof exists for') $)

  $( Introduce some variable names we will use to represent well-formed
     formulas (wff's). $)
  $v ph $. $( Greek phi $)
  $v ps $.  $( Greek psi $)
  $v ch $.  $( Greek chi $)
  $v th $.  $( Greek theta $)
  $v ta $.  $( Greek tau $)

  $(
     Specify some variables that we will use to represent wff's.
     The fact that a variable represents a wff is relevant only to a theorem
     referring to that variable, so we may use $f hypotheses.  The symbol
     ` wff ` specifies that the variable that follows it represents a wff.
  $)

  $( Let variable ` ph ` be a wff. $)
  wph $f wff ph $.
  $( Let variable ` ps ` be a wff. $)
  wps $f wff ps $.
  $( Let variable ` ch ` be a wff. $)
  wch $f wff ch $.
  $( Let variable ` th ` be a wff. $)
  wth $f wff th $.
  $( Let variable ` ta ` be a wff. $)
  wta $f wff ta $.

  $(
     Recursively define wff's.
  $)

  $( If ` ph ` is a wff, so is ` -. ph ` or "not ` ph ` ".  Part of the
     recursive definition of a wff (well-formed formula).  In classical logic
     (which is our logic), a wff is interpreted as either true or false.
     So if ` ph ` is true, then ` -. ph ` is false; if ` ph ` is false, then
     ` -. ph ` is true.  Traditionally, Greek letters are used to represent
     wffs, and we follow this convention.  In propositional calculus, we define
     only wffs built up from other wffs, i.e. there is no starting or "atomic"
     wff.  Later, in predicate calculus, we will extend the basic wff
     definition by including atomic wffs ( ~ weq and ~ wel ). $)
  wn $a wff -. ph $.

  $( If ` ph ` and ` ps ` are wff's, so is ` ( ph -> ps ) ` or " ` ph ` implies
     ` ps ` ."  Part of the recursive definition of a wff.  The resulting wff
     is (interpreted as) false when ` ph ` is true and ` ps ` is false; it is
     true otherwise.  (Think of the truth table for an OR gate with input
     ` ph ` connected through an inverter.)  The left-hand wff is called the
     antecedent, and the right-hand wff is called the consequent.  In the case
     of ` ( ph -> ( ps -> ch ) ) ` , the middle ` ps ` may be informally called
     either an antecedent or part of the consequent depending on context. $)
  wi $a wff ( ph -> ps ) $.

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        The axioms of propositional calculus
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $(
     Postulate the three axioms of classical propositional calculus.
  $)

  $( Axiom _Simp_.  Axiom A1 of [Margaris] p. 49.  One of the 3 axioms of
     propositional calculus.  The 3 axioms are also given as Definition 2.1
     of [Hamilton] p. 28.  This axiom is called _Simp_ or "the principle of
     simplification" in _Principia Mathematica_ (Theorem *2.02 of
     [WhiteheadRussell] p. 100) because "it enables us to pass from the joint
     assertion of ` ph ` and ` ps ` to the assertion of ` ph ` simply."

     Propositional calculus (axioms ~ ax-1 through ~ ax-3 and rule ~ ax-mp )
     can be thought of as asserting formulas that are universally "true" when
     their variables are replaced by any combination of "true" and "false".
     Propositional calculus was first formalized by Frege in 1879, using as
     his axioms (in addition to rule ~ ax-mp ) the wffs ~ ax-1 , ~ ax-2 ,
     ~ pm2.04 , ~ con3 , ~ nega , and ~ negb .  Around 1930, Lukasiewicz
     simplified the system by eliminating the third (which follows from the
     first two, as you can see by looking at the proof of ~ pm2.04 ) and
     replacing the last three with our ~ ax-3 .  (Thanks to Ted Ulrich
     for this information.)

     The theorems of propositional calculus are also called _tautologies_.
     Tautologies can be proved very simply using truth tables, based on the
     true/false interpretation of propositional calculus.  To do this, we
     assign all possible combinations of true and false to the wff variables
     and verify that the result (using the rules described in ~ wi and ~ wn )
     always evaluates to true.  This is called the _semantic_ approach.  Our
     approach is called the _syntactic_ approach, in which everything is
     derived from axioms.  A metatheorem called the Completeness Theorem for
     Propositional Calculus shows that the two approaches are equivalent and
     even provides an algorithm for automatically generating syntactic proofs
     from a truth table.  Those proofs, however, tend to be long, and the
     much shorter proofs that we show here were found manually. $)
  ax-1 $a |- ( ph -> ( ps -> ph ) ) $.

  $( Axiom _Frege_.  Axiom A2 of [Margaris] p. 49.  One of the 3 axioms of
     propositional calculus.  It distributes an antecedent over two
     consequents.  This axiom was part of Frege's original system and is known
     as _Frege_ in the literature.  It is also proved as Theorem *2.77 of
     [WhiteheadRussell] p. 108.  $)
  ax-2 $a |- ( ( ph -> ( ps -> ch ) ) -> ( ( ph -> ps ) -> ( ph -> ch ) ) ) $.

  $( Axiom _Transp_.  Axiom A3 of [Margaris] p. 49.  One of the 3 axioms of
     propositional calculus.  It swaps or transposes the order of the
     consequents when negation is removed.  An informal example is that the
     statement "if there are no clouds in the sky, it is not raining" implies
     the statement "if it is raining, there are clouds in the sky."  This
     axiom is called _Transp_ or "the principle of transposition" in
     _Principia Mathematica_ (Theorem *2.17 of [WhiteheadRussell] p. 103).  $)
  ax-3 $a |- ( ( -. ph -> -. ps ) -> ( ps -> ph ) ) $.

  $(
     Postulate the modus ponens rule of inference.
  $)

  ${
    $( Minor premise for modus ponens. $)
    min $e |- ph $.
    $( Major premise for modus ponens. $)
    maj $e |- ( ph -> ps ) $.
    $( Rule of Modus Ponens. The postulated inference rule of propositional
       calculus.  See e.g. Rule 1 of [Hamilton] p. 73.  The rule says, "if
       ` ph ` is true, and ` ph ` implies ` ps ` , then ` ps ` must also be
       true."  This rule is sometimes called "detachment", since it detaches
       the minor premise from the major premise. $)
    ax-mp $a |- ps $.
  $}

  $(
     ~ ax-1 , ~ ax-2 , ~ ax-3 , and ~ ax-mp are the complete set of
     postulates for propositional calculus.  Some additional $a statements
     are used later to introduce defined terms.
  $)

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Logical implication
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

$( The results in this section make use of the first 2 axioms only.  In
   an implication, the wff before the arrow is called the 'antecedent'
   and the wff after the arrow is called the 'consequent.' $)

$( We will use the following descriptive terms very loosely:  A 'theorem'
   usually has no $e hypotheses.  An 'inference' has one or more $e hypotheses.
   A 'deduction' is an inference in which the hypotheses and the result
   share the same antecedent. $)

  ${
    $( Premise for ~ a1i . $)
    a1i.1 $e |- ph $.
    $( Inference derived from axiom ~ ax-1 .  See ~ a1d for an explanation of
       our informal use of the terms "inference" and "deduction". $)
    a1i $p |- ( ps -> ph ) $=
      ( wi ax-1 ax-mp ) ABADCABEF $.
      $( [5-Aug-93] $)
  $}

  ${
    $( Premise for ~ a2i . $)
    a2i.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Inference derived from axiom ~ ax-2 . $)
    a2i $p |- ( ( ph -> ps ) -> ( ph -> ch ) ) $=
      ( wi ax-2 ax-mp ) ABCEEABEACEEDABCFG $.
      $( [5-Aug-93] $)
  $}

  $( Principle of identity.  Theorem *2.08 of [WhiteheadRussell] p. 101.
     For another version of the proof directly from axioms, see ~ id1 . $)
  id $p |- ( ph -> ph ) $=
    ( wi ax-1 a2i ax-mp ) AAABZBFAACAFAAFCDE $.
    $( [5-Aug-93] $)

  $( Principle of identity.  Theorem *2.08 of [WhiteheadRussell] p. 101.  This
     version is proved directly from the axioms for demonstration purposes.
     This proof is identical, step for step, to the proofs of Theorem 1 of
     [Margaris] p. 51 and Example 2.7(a) of [Hamilton] p. 31.
     For a shorter version of the proof that takes advantage of a previously
     proved inference, see ~ id . $)
  id1 $p |- ( ph -> ph ) $=
    ( wi ax-1 ax-2 ax-mp ) AAABZBZFAACAFABBGFBAFCAFADEE $.
    $( [5-Aug-93] $)

  $( Principle of identity with antecedent. $)
  idd $p |- ( ph -> ( ps -> ps ) ) $=
    ( wi id a1i ) BBCABDE $.
    $( [26-Nov-95] $)

  ${
    $( First of 2 premises for ~ syl . $)
    syl.1 $e |- ( ph -> ps ) $.
    $( First of 2 premises for ~ syl . $)
    syl.2 $e |- ( ps -> ch ) $.
    $( An inference version of the transitive laws for implication ~ syl1 and
       ~ syl2 , which Russell and Whitehead call "the principle of the
       syllogism...because...the syllogism in Barbara is derived from them"
       (quote after Theorem *2.06 of [WhiteheadRussell] p. 101).

       (A bit of trivia:  this is the most commonly referenced assertion in our
       database.  In second place is ~ ax-mp , followed by ~ visset , ~ bitr ,
       ~ imp , and ~ exp . The Metamath program command 'show usage' shows the
       number of references.)  $)

    syl $p |- ( ph -> ch ) $=
      ( wi a1i a2i ax-mp ) ABFACFDABCBCFAEGHI $.
      $( [5-Aug-93] $)
  $}

  ${
    $( Premise for ~ com12 . $)
    com12.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Inference that swaps (commutes) antecedents in an implication. $)
    com12 $p |- ( ps -> ( ph -> ch ) ) $=
      ( wi ax-1 a2i syl ) BABEACEBAFABCDGH $.
      $( [5-Aug-93] $)
  $}

  ${
    a1d.1 $e |- ( ph -> ps ) $.
    $( Deduction introducing an embedded antecedent.

       _Naming convention_:  We often call a theorem a "deduction" and suffix
       its label with "d" whenever the hypotheses and conclusion are each
       prefixed with the same antecedent.  This allows us to use the theorem in
       places where (in traditional textbook formalizations) the standard
       Deduction Theorem would be used; here ` ph ` would be replaced with a
       conjunction ( ~ df-an ) of the hypotheses of the would-be deduction.  By
       contrast, we tend to call the simpler version with no common antecedent
       an "inference" and suffix its label with "i"; compare theorem ~ a1i .
       Finally, a "theorem" would be the form with no hypotheses; in this case
       the "theorem" form would be the original axiom ~ ax-1 . In propositional
       calculus we usually prove the theorem form first without a suffix on its
       label (e.g.  ~ pm2.43 vs.  ~ pm2.43i vs.  ~ pm2.43d ), but (much) later
       we often suffix the theorem form's label with "t" as in ~ negnegt vs.
       ~ negneg , especially when our "weak deduction theorem" ~ dedth is used
       to prove the theorem form from its inference form.  When an inference is
       converted to a theorem by eliminating an "is a set" hypothesis, we
       sometimes suffix the theorem form with "g" (for somewhat misnamed
       "generalized") as in ~ uniex vs.  ~ uniexg . $)
    a1d $p |- ( ph -> ( ch -> ps ) ) $=
      ( wi a1i com12 ) CABABECDFG $.
      $( [5-Aug-93] $)
  $}

  ${
    a2d.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    $( Deduction distributing an embedded antecedent. $)
    a2d $p |- ( ph -> ( ( ps -> ch ) -> ( ps -> th ) ) ) $=
      ( wi ax-2 syl ) ABCDFFBCFBDFFEBCDGH $.
      $( [23-Jun-94] $)
  $}

  $( A closed form of syllogism (see ~ syl ).  Theorem *2.05 of
     [WhiteheadRussell] p. 100. $)
  syl1 $p |- ( ( ph -> ps ) -> ( ( ch -> ph ) -> ( ch -> ps ) ) ) $=
    ( wi ax-1 a2d ) ABDZCABGCEF $.
    $( [5-Aug-93] $)

  $( A closed form of syllogism (see ~ syl ).  Theorem *2.06 of
     [WhiteheadRussell] p. 100. $)
  syl2 $p |- ( ( ph -> ps ) -> ( ( ps -> ch ) -> ( ph -> ch ) ) ) $=
    ( wi syl1 com12 ) BCDABDACDBCAEF $.
    $( [5-Aug-93] $)

  ${
    $( Premise for ~ syl3 . $)
    syl3.1 $e |- ( ph -> ps ) $.
    $( Inference adding common antecedents in an implication. $)
    syl3 $p |- ( ( ch -> ph ) -> ( ch -> ps ) ) $=
      ( wi a1i a2i ) CABABECDFG $.
      $( [5-Aug-93] $)
  $}

  ${
    syl4.1 $e |- ( ph -> ps ) $.
    $( Inference adding common consequents in an implication, thereby
       interchanging the original antecedent and consequent. $)
    syl4 $p |- ( ( ps -> ch ) -> ( ph -> ch ) ) $=
      ( wi syl2 ax-mp ) ABEBCEACEEDABCFG $.
      $( [5-Aug-93] $)
  $}

  ${
    syl34.1 $e |- ( ph -> ps ) $.
    syl34.2 $e |- ( ch -> th ) $.
    $( Inference joining two implications. $)
    syl34 $p |- ( ( ps -> ch ) -> ( ph -> th ) ) $=
      ( wi syl3 syl4 syl ) BCGBDGADGCDBFHABDEIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    3syl.1 $e |- ( ph -> ps ) $.
    3syl.2 $e |- ( ps -> ch ) $.
    3syl.3 $e |- ( ch -> th ) $.
    $( Inference chaining two syllogisms. $)
    3syl $p |- ( ph -> th ) $=
      ( syl ) ACDABCEFHGH $.
      $( [5-Aug-93] $)
  $}

  ${
    syl5.1 $e |- ( ph -> ( ps -> ch ) ) $.
    syl5.2 $e |- ( th -> ps ) $.
    $( A syllogism rule of inference.  The second premise is used to replace
       the second antecedent of the first premise. $)
    syl5 $p |- ( ph -> ( th -> ch ) ) $=
      ( wi syl4 syl ) ABCGDCGEDBCFHI $.
      $( [5-Aug-93] $)
  $}

  ${
    syl6.1 $e |- ( ph -> ( ps -> ch ) ) $.
    syl6.2 $e |- ( ch -> th ) $.
    $( A syllogism rule of inference.  The second premise is used to replace
       the consequent of the first premise. $)
    syl6 $p |- ( ph -> ( ps -> th ) ) $=
      ( wi syl3 syl ) ABCGBDGECDBFHI $.
      $( [5-Aug-93] $)
  $}

  ${
    syl7.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    syl7.2 $e |- ( ta -> ch ) $.
    $( A syllogism rule of inference.  The second premise is used to replace
       the third antecedent of the first premise. $)
    syl7 $p |- ( ph -> ( ps -> ( ta -> th ) ) ) $=
      ( wi syl4 syl6 ) ABCDHEDHFECDGIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    syl8.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    syl8.2 $e |- ( th -> ta ) $.
    $( A syllogism rule of inference.  The second premise is used to replace
       the consequent of the first premise. $)
    syl8 $p |- ( ph -> ( ps -> ( ch -> ta ) ) ) $=
      ( wi syl3 syl6 ) ABCDHCEHFDECGIJ $.
      $( [1-Aug-94] $)
  $}

  ${
    syl3d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction adding nested antecedents. $)
    syl3d $p |- ( ph -> ( ( th -> ps ) -> ( th -> ch ) ) ) $=
      ( wi a1d a2d ) ADBCABCFDEGH $.
      $( [5-Aug-93] $)
  $}

  ${
    syld.1 $e |- ( ph -> ( ps -> ch ) ) $.
    syld.2 $e |- ( ph -> ( ch -> th ) ) $.
    $( Syllogism deduction.  (The proof was shortened by Mel L. O'Cat,
       7-Aug-04.) $)
    syld $p |- ( ph -> ( ps -> th ) ) $=
      ( wi syl3d a2i ax-mp ) ABCGZGABDGZGEAKLACDBFHIJ $.
      $( [9-Aug-04] $) $( [5-Aug-93] $)
  $}

  ${
    syl4d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction adding nested consequents. $)
    syl4d $p |- ( ph -> ( ( ch -> th ) -> ( ps -> th ) ) ) $=
      ( wi syl2 syl ) ABCFCDFBDFFEBCDGH $.
      $( [3-Apr-94] $)
  $}

  ${
    syl34d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    syl34d.2 $e |- ( ph -> ( th -> ta ) ) $.
    $( Deduction combining antecedents and consequents. $)
    syl34d $p |- ( ph -> ( ( ch -> th ) -> ( ps -> ta ) ) ) $=
      ( wi syl4d syl3d syld ) ACDHBDHBEHABCDFIADEBGJK $.
      $( [7-Aug-94] $)
  $}

  $( This theorem, called "Assertion," can be thought of as closed form of
     modus ponens.  Theorem *2.27 of [WhiteheadRussell] p. 104. $)
  pm2.27 $p |- ( ph -> ( ( ph -> ps ) -> ps ) ) $=
    ( wi id com12 ) ABCZABFDE $.
    $( [5-Aug-93] $)

  $( Swap antecedents.  Theorem *2.04 of [WhiteheadRussell] p. 100. $)
  pm2.04 $p |- ( ( ph -> ( ps -> ch ) ) -> ( ps -> ( ph -> ch ) ) ) $=
    ( wi ax-2 ax-1 syl5 ) ABCDDABDACDBABCEBAFG $.
    $( [5-Aug-93] $)

  $( Theorem *2.83 of [WhiteheadRussell] p. 108. $)
  pm2.83 $p |-  ( ( ph -> ( ps -> ch ) ) -> ( ( ph -> ( ch -> th ) ) ->
                ( ph -> ( ps -> th ) ) ) ) $=
    ( wi syl2 syl3 a2d ) ABCEZEACDEZBDEZIJKEABCDFGH $.
    $( [13-Jan-05] $) $( [3-Jan-05] $)

  ${
    com3.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    $( Commutation of antecedents.  Swap 2nd and 3rd. $)
    com23 $p |- ( ph -> ( ch -> ( ps -> th ) ) ) $=
      ( wi pm2.04 syl ) ABCDFFCBDFFEBCDGH $.
      $( [5-Aug-93] $)

    $( Commutation of antecedents.  Swap 1st and 3rd. $)
    com13 $p |- ( ch -> ( ps -> ( ph -> th ) ) ) $=
      ( wi com12 com23 ) BCADFBACDABCDFEGHG $.
      $( [25-Apr-94] $)

    $( Commutation of antecedents.  Rotate left. $)
    com3l $p |- ( ps -> ( ch -> ( ph -> th ) ) ) $=
      ( com23 com13 ) ACBDABCDEFG $.
      $( [25-Apr-94] $)

    $( Commutation of antecedents.  Rotate right. $)
    com3r $p |- ( ch -> ( ph -> ( ps -> th ) ) ) $=
      ( com3l ) BCADABCDEFF $.
      $( [25-Apr-94] $)
  $}

  ${
    com4.1 $e |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $.
    $( Commutation of antecedents. Swap 3rd and 4th. $)
    com34 $p |- ( ph -> ( ps -> ( th -> ( ch -> ta ) ) ) ) $=
      ( wi pm2.04 syl6 ) ABCDEGGDCEGGFCDEHI $.
      $( [25-Apr-94] $)

    $( Commutation of antecedents. Swap 2nd and 4th. $)
    com24 $p |- ( ph -> ( th -> ( ch -> ( ps -> ta ) ) ) ) $=
      ( wi com34 com23 ) ADBCEABDCEGABCDEFHIH $.
      $( [25-Apr-94] $)

    $( Commutation of antecedents. Swap 1st and 4th. $)
    com14 $p |- ( th -> ( ps -> ( ch -> ( ph -> ta ) ) ) ) $=
      ( wi com34 com13 ) DBACEABDCEGABCDEFHIH $.
      $( [25-Apr-94] $)

    $( Commutation of antecedents.  Rotate left.  (The proof
       was shortened by Mel L. O'Cat, 15-Aug-04.) $)
    com4l $p |- ( ps -> ( ch -> ( th -> ( ph -> ta ) ) ) ) $=
      ( wi com14 com3l ) DBCAEGABCDEFHI $.
      $( [16-Aug-04] $) $( [25-Apr-94] $)

    $( Commutation of antecedents.  Rotate twice. $)
    com4t $p |- ( ch -> ( th -> ( ph -> ( ps -> ta ) ) ) ) $=
      ( com4l ) BCDAEABCDEFGG $.
      $( [25-Apr-94] $)

    $( Commutation of antecedents.  Rotate right. $)
    com4r $p |- ( th -> ( ph -> ( ps -> ( ch -> ta ) ) ) ) $=
      ( com4t com4l ) CDABEABCDEFGH $.
      $( [25-Apr-94] $)
  $}

  ${
    a1dd.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction introducing a nested embedded antecedent. $)
    a1dd $p |- ( ph -> ( ps -> ( th -> ch ) ) ) $=
      ( wi a1d com23 ) ADBCABCFDEGH $.
      $( [18-Dec-04] $) $( [17-Dec-04] $)
  $}

  ${
    mp2.1 $e |- ph $.
    mp2.2 $e |- ps $.
    mp2.3 $e |- ( ph -> ( ps -> ch ) ) $.
    $( A double modus ponens inference. $)
    mp2 $p |- ch $=
      ( wi ax-mp ) BCEABCGDFHH $.
      $( [5-Apr-94] $)
  $}

  ${
    mpi.1 $e |- ps $.
    mpi.2 $e |- ( ph -> ( ps -> ch ) ) $.
    $( A nested modus ponens inference. $)
    mpi $p |- ( ph -> ch ) $=
      ( wi com12 ax-mp ) BACFDABCEGH $.
      $( [5-Aug-93] $)
  $}

  ${
    mpii.1 $e |- ch $.
    mpii.2 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    $( A doubly nested modus ponens inference. $)
    mpii $p |- ( ph -> ( ps -> th ) ) $=
      ( wi com23 mpi ) ACBDGEABCDFHI $.
      $( [31-Dec-93] $)
  $}

  ${
    mpd.1 $e |- ( ph -> ps ) $.
    mpd.2 $e |- ( ph -> ( ps -> ch ) ) $.
    $( A modus ponens deduction. $)
    mpd $p |- ( ph -> ch ) $=
      ( wi a2i ax-mp ) ABFACFDABCEGH $.
      $( [5-Aug-93] $)
  $}

  ${
    mpdd.1 $e |- ( ph -> ( ps -> ch ) ) $.
    mpdd.2 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    $( A nested modus ponens deduction. $)
    mpdd $p |- ( ph -> ( ps -> th ) ) $=
      ( wi a2d mpd ) ABCGBDGEABCDFHI $.
      $( [13-Dec-04] $) $( [12-Dec-04] $)
  $}

  ${
    mpid.1 $e |- ( ph -> ch ) $.
    mpid.2 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    $( A nested modus ponens deduction. $)
    mpid $p |- ( ph -> ( ps -> th ) ) $=
      ( a1d mpdd ) ABCDACBEGFH $.
      $( [16-Dec-04] $) $( [14-Dec-04] $)
  $}

  ${
    mpcom.1 $e |- ( ps -> ph ) $.
    mpcom.2 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Modus ponens inference with commutation of antecedents. $)
    mpcom $p |- ( ps -> ch ) $=
      ( com12 mpd ) BACDABCEFG $.
      $( [17-Mar-96] $)
  $}

  ${
    syldd.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    syldd.2 $e |- ( ph -> ( ps -> ( th -> ta ) ) ) $.
    $( Nested syllogism deduction. $)
    syldd $p |- ( ph -> ( ps -> ( ch -> ta ) ) ) $=
      ( wi syl1 syl6 mpdd ) ABCDHZCEHZFABDEHLMHGDECIJK $.
      $( [13-Dec-04] $) $( [12-Dec-04] $)
  $}

  ${
    sylcom.1 $e |- ( ph -> ( ps -> ch ) ) $.
    sylcom.2 $e |- ( ps -> ( ch -> th ) ) $.
    $( Syllogism inference with commutation of antecedents. $)
    sylcom $p |- ( ph -> ( ps -> th ) ) $=
      ( com12 syld ) BADBACDABCEGFHG $.
      $( [30-Aug-04] $) $( [29-Aug-04] $)
  $}

  ${
    syli.1 $e |- ( ps -> ( ph -> ch ) ) $.
    syli.2 $e |- ( ch -> ( ph -> th ) ) $.
    $( Syllogism inference with common nested antecedent. $)
    syli $p |- ( ps -> ( ph -> th ) ) $=
      ( com12 sylcom ) BACDECADFGH $.
      $( [5-Nov-04] $) $( [4-Nov-04] $)
  $}

  ${
    syl5d.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    syl5d.2 $e |- ( ph -> ( ta -> ch ) ) $.
    $( A nested syllogism deduction.  (The proof was shortened by Josh
       Purinton, 29-Dec-00.) $)
    syl5d $p |- ( ph -> ( ps -> ( ta -> th ) ) ) $=
      ( wi syl4d syld ) ABCDHEDHFAECDGIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    syl6d.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    syl6d.2 $e |- ( ph -> ( th -> ta ) ) $.
    $( A nested syllogism deduction.  (The proof was shortened by Josh
       Purinton, 29-Dec-00.) $)
    syl6d $p |- ( ph -> ( ps -> ( ch -> ta ) ) ) $=
      ( wi syl3d syld ) ABCDHCEHFADECGIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    syl9.1 $e |- ( ph -> ( ps -> ch ) ) $.
    syl9.2 $e |- ( th -> ( ch -> ta ) ) $.
    $( A nested syllogism inference with different antecedents.  (The proof
       was shortened by Josh Purinton, 29-Dec-00.) $)
    syl9 $p |- ( ph -> ( th -> ( ps -> ta ) ) ) $=
      ( wi a1i syl5d ) ADCEBDCEHHAGIFJ $.
      $( [5-Aug-93] $)
  $}

  ${
    syl9r.1 $e |- ( ph -> ( ps -> ch ) ) $.
    syl9r.2 $e |- ( th -> ( ch -> ta ) ) $.
    $( A nested syllogism inference with different antecedents. $)
    syl9r $p |- ( th -> ( ph -> ( ps -> ta ) ) ) $=
      ( wi syl9 com12 ) ADBEHABCDEFGIJ $.
      $( [5-Aug-93] $)
  $}

  $( Absorption of redundant antecedent.  Also called the "Contraction" or
     "Hilbert" axiom.  Theorem *2.43 of [WhiteheadRussell] p. 106.  (The proof
     was shortened by Mel L. O'Cat, 15-Aug-04.) $)
  pm2.43 $p |- ( ( ph -> ( ph -> ps ) ) -> ( ph -> ps ) ) $=
    ( wi pm2.27 a2i ) AABCBABDE $.
    $( [16-Aug-04] $) $( [5-Aug-93] $)

  ${
    pm2.43i.1 $e |- ( ph -> ( ph -> ps ) ) $.
    $( Inference absorbing redundant antecedent. $)
    pm2.43i $p |- ( ph -> ps ) $=
      ( wi pm2.43 ax-mp ) AABDZDGCABEF $.
      $( [5-Aug-93] $)
  $}

  ${
    pm2.43d.1 $e |- ( ph -> ( ps -> ( ps -> ch ) ) ) $.
    $( Deduction absorbing redundant antecedent. $)
    pm2.43d $p |- ( ph -> ( ps -> ch ) ) $=
      ( wi pm2.43 syl ) ABBCEZEHDBCFG $.
      $( [18-Aug-93] $)
  $}

  ${
    pm2.43a.1 $e |- ( ps -> ( ph -> ( ps -> ch ) ) ) $.

    $( Inference absorbing redundant antecedent. $)
    pm2.43a $p |- ( ps -> ( ph -> ch ) ) $=
      ( wi com23 pm2.43i ) BACEBABCDFG $.
      $( [7-Nov-95] $)

    $( Inference absorbing redundant antecedent. $)
    pm2.43b $p |- ( ph -> ( ps -> ch ) ) $=
      ( pm2.43a com12 ) BACABCDEF $.
      $( [31-Oct-95] $)
  $}

  ${
    sylc.1 $e |- ( ph -> ( ps -> ch ) ) $.
    sylc.2 $e |- ( th -> ph ) $.
    sylc.3 $e |- ( th -> ps ) $.
    $( A syllogism inference combined with contraction. $)
    sylc $p |- ( th -> ch ) $=
      ( wi syl mpd ) DBCGDABCHFEIJ $.
      $( [4-May-94] $)
  $}

  $( Converse of axiom ~ ax-2 .  Theorem *2.86 of [WhiteheadRussell] p. 108. $)
  pm2.86 $p |- ( ( ( ph -> ps ) -> ( ph -> ch ) ) ->
               ( ph -> ( ps -> ch ) ) ) $=
    ( wi ax-1 syl4 com23 ) ABDZACDZDBACBHIBAEFG $.
    $( [25-Apr-94] $)

  ${
    pm2.86i.1 $e |- ( ( ph -> ps ) -> ( ph -> ch ) ) $.
    $( Inference based on ~ pm2.86 . $)
    pm2.86i $p |- ( ph -> ( ps -> ch ) ) $=
      ( wi pm2.86 ax-mp ) ABEACEEABCEEDABCFG $.
      $( [5-Aug-93] $)
  $}

  ${
    pm2.86d.1 $e |- ( ph -> ( ( ps -> ch ) -> ( ps -> th ) ) ) $.
    $( Deduction based on ~ pm2.86 . $)
    pm2.86d $p |- ( ph -> ( ps -> ( ch -> th ) ) ) $=
      ( wi pm2.86 syl ) ABCFBDFFBCDFFEBCDGH $.
      $( [29-Jun-95] $)
  $}

  $( The Linearity Axiom of the infinite-valued sentential logic (L-infinity)
     of Lukasiewicz.   (Contributed by Mel L. O'Cat, 12-Aug-04.) $)
  loolin $p |- ( ( ( ph -> ps ) -> ( ps -> ph ) ) -> ( ps -> ph ) ) $=
    ( wi ax-1 syl4 pm2.43d ) ABCZBACZCBABGHBADEF $.
    $( [14-Aug-04] $) $( [13-Aug-04] $)

  $( An alternate for the Linearity Axiom of the infinite-valued sentential
     logic (L-infinity) of Lukasiewicz, due to Barbara Wozniakowska, _Reports
     on Mathematical Logic_ 10, 129-137 (1978).  (Contributed by Mel L. O'Cat,
     8-Aug-04.) $)
  loowoz $p |- ( ( ( ph -> ps ) -> ( ph -> ch ) ) ->
                 ( ( ps -> ph ) -> ( ps -> ch ) ) ) $=
    ( wi ax-1 syl4 a2d ) ABDZACDZDBACBHIBAEFG $.
    $( [9-Aug-04] $) $( [9-Aug-04] $)

  $( This dummy theorem and the theorems that reference it may be ignored.
     (The purpose of any theorems that reference it is to provide placeholders
     for possible future theorems.  The placeholder prevents theorems from
     being renumbered when the finalized theorem replaces the placeholder.
     This helps conserve bandwidth during mirror site updates.) $)
  xxxid $p |- ( ph -> ph ) $=
    ( id ) AB $.
    $( [5-Aug-93] $)

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Logical negation
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

$( This section makes our first use of the third axiom of propositonal
   calculus. $)

  ${
    a3i.1 $e |- ( -. ph -> -. ps ) $.
    $( Inference rule derived from axiom ~ ax-3 . $)
    a3i $p |- ( ps -> ph ) $=
      ( wn wi ax-3 ax-mp ) ADBDEBAECABFG $.
      $( [5-Aug-93] $)
  $}

  ${
    a3d.1 $e |- ( ph -> ( -. ps -> -. ch ) ) $.
    $( Deduction derived from axiom ~ ax-3 . $)
    a3d $p |- ( ph -> ( ch -> ps ) ) $=
      ( wn wi ax-3 syl ) ABECEFCBFDBCGH $.
      $( [26-Mar-95] $)
  $}

  $( From a wff and its negation, anything is true.  Theorem *2.21 of
     [WhiteheadRussell] p. 104.  Also called the Duns Scotus law. $)
  pm2.21 $p |- ( -. ph -> ( ph -> ps ) ) $=
    ( wn ax-1 a3d ) ACZBAFBCDE $.
    $( [5-Aug-93] $)

  $( Theorem *2.24 of [WhiteheadRussell] p. 104. $)
  pm2.24 $p |-  ( ph -> ( -. ph -> ps ) ) $=
    ( wn pm2.21 com12 ) ACABABDE $.
    $( [6-Jan-05] $) $( [3-Jan-05] $)

  ${
    pm2.21i.1 $e |- -. ph $.
    $( A contradiction implies anything.  Inference from ~ pm2.21 . $)
    pm2.21i $p |- ( ph -> ps ) $=
      ( wn a1i a3i ) BAADBDCEF $.
      $( [16-Sep-93] $)
  $}

  ${
    pm2.21d.1 $e |- ( ph -> -. ps ) $.
    $( A contradiction implies anything.  Deduction from ~ pm2.21 . $)
    pm2.21d $p |- ( ph -> ( ps -> ch ) ) $=
      ( wn a1d a3d ) ACBABECEDFG $.
      $( [10-Feb-96] $)
  $}

  $( Proof by contradiction.  Theorem *2.18 of [WhiteheadRussell] p. 103.
     Also called the Law of Clavius. $)
  pm2.18 $p |- ( ( -. ph -> ph ) -> ph ) $=
    ( wn wi pm2.21 a2i a3d pm2.43i ) ABZACZAIAIHAIBZAJDEFG $.
    $( [5-Aug-93] $)

  $( Peirce's axiom.  This odd-looking theorem is the "difference" between
     an intuitionistic system of propositional calculus and a classical system
     and is not accepted by intuitionists.  When Peirce's axiom is added to an
     intuitionistic system, the system becomes equivalent to our classical
     system ~ ax-1 through ~ ax-3 .  A curious fact about this
     theorem is that it requires ~ ax-3 for its proof even though the
     result has no negations in it. $)
  peirce $p |- ( ( ( ph -> ps ) -> ph ) -> ph ) $=
    ( wi wn pm2.21 syl4 pm2.18 syl ) ABCZACADZACAJIAABEFAGH $.
    $( [5-Aug-93] $)

  $( The Inversion Axiom of the infinite-valued sentential logic (L-infinity)
     of Lukasiewicz.  Using ~ dfor2 , we can see that this essentially
     expresses "disjunction commutes."  Theorem *2.69 of [WhiteheadRussell]
     p. 108. $)
  looinv $p |- ( ( ( ph -> ps ) -> ps ) -> ( ( ps -> ph ) -> ph ) ) $=
    ( wi syl2 peirce syl6 ) ABCZBCBACGACAGBADABEF $.
    $( [20-Aug-04] $) $( [12-Aug-04] $)

  $( Double negation.  Theorem *2.14 of [WhiteheadRussell] p. 102.  (The proof
     was shortened by David Harvey, 5-Sep-99.  An even shorter proof found by
     Josh Purinton, 29-Dec-00.) $)
  nega $p |- ( -. -. ph -> ph ) $=
    ( wn wi pm2.21 pm2.18 syl ) ABZBGACAGADAEF $.
    $( [5-Aug-93] $)

  $( Converse of double negation.  Theorem *2.12 of [WhiteheadRussell]
     p. 101. $)
  negb $p |- ( ph -> -. -. ph ) $=
    ( wn nega a3i ) ABZBAECD $.
    $( [5-Aug-93] $)

  $( Reductio ad absurdum.  Theorem *2.01 of [WhiteheadRussell] p. 100. $)
  pm2.01 $p |- ( ( ph -> -. ph ) -> -. ph ) $=
    ( wn wi nega syl4 pm2.18 syl ) AABZCHBZHCHIAHADEHFG $.
    $( [18-Aug-93] $)

  ${
    pm2.01d.1 $e |- ( ph -> ( ps -> -. ps ) ) $.
    $( Deduction based on reductio ad absurdum. $)
    pm2.01d $p |- ( ph -> -. ps ) $=
      ( wn wi pm2.01 syl ) ABBDZEHCBFG $.
      $( [18-Aug-93] $)
  $}

  $( Contraposition.  Theorem *2.03 of [WhiteheadRussell] p. 100. $)
  con2 $p |- ( ( ph -> -. ps ) -> ( ps -> -. ph ) ) $=
    ( wn wi nega syl4 a3d ) ABCZDACZBICAHAEFG $.
    $( [5-Aug-93] $)

  ${
    con2d.1 $e |- ( ph -> ( ps -> -. ch ) ) $.
    $( A contraposition deduction. $)
    con2d $p |- ( ph -> ( ch -> -. ps ) ) $=
      ( wn wi con2 syl ) ABCEFCBEFDBCGH $.
      $( [19-Aug-93] $)
  $}

  $( Contraposition.  Theorem *2.15 of [WhiteheadRussell] p. 102. $)
  con1 $p |- ( ( -. ph -> ps ) -> ( -. ps -> ph ) ) $=
    ( wn wi negb syl3 a3d ) ACZBDABCZBICHBEFG $.
    $( [5-Aug-93] $)

  ${
    con1d.1 $e |- ( ph -> ( -. ps -> ch ) ) $.
    $( A contraposition deduction. $)
    con1d $p |- ( ph -> ( -. ch -> ps ) ) $=
      ( wn wi con1 syl ) ABECFCEBFDBCGH $.
      $( [5-Aug-93] $)
  $}

  $( Contraposition.  Theorem *2.16 of [WhiteheadRussell] p. 103. $)
  con3 $p |- ( ( ph -> ps ) -> ( -. ps -> -. ph ) ) $=
    ( wi wn negb syl3 con2d ) ABCABDZBHDABEFG $.
    $( [5-Aug-93] $)

  ${
    con3d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( A contraposition deduction. $)
    con3d $p |- ( ph -> ( -. ch -> -. ps ) ) $=
      ( wi wn con3 syl ) ABCECFBFEDBCGH $.
      $( [5-Aug-93] $)
  $}

  ${
    con1.a $e |- ( -. ph -> ps ) $.
    $( A contraposition inference. $)
    con1i $p |- ( -. ps -> ph ) $=
      ( wn negb syl a3i ) ABDZADBHDCBEFG $.
      $( [5-Aug-93] $)
  $}

  ${
    con2.a $e |- ( ph -> -. ps ) $.
    $( A contraposition inference. $)
    con2i $p |- ( ps -> -. ph ) $=
      ( wn nega syl a3i ) ADZBHDABDAECFG $.
      $( [5-Aug-93] $)
  $}

  ${
    con3.a $e |- ( ph -> ps ) $.
    $( A contraposition inference. $)
    con3i $p |- ( -. ps -> -. ph ) $=
      ( wn nega syl con1i ) ADZBHDABAECFG $.
      $( [5-Aug-93] $)
  $}

  $( Theorem *2.36 of [WhiteheadRussell] p. 105. $)
  pm2.36 $p |-  ( ( ps -> ch ) -> ( ( -. ph -> ps ) -> ( -. ch -> ph ) ) ) $=
    ( wi wn syl1 con1 syl6 ) BCDAEZBDICDCEADBCIFACGH $.
    $( [8-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.37 of [WhiteheadRussell] p. 105. $)
  pm2.37 $p |-  ( ( ps -> ch ) -> ( ( -. ps -> ph ) -> ( -. ph -> ch ) ) ) $=
    ( wn wi con1 syl4d com12 ) BDAEZBCEADZCEIJBCBAFGH $.
    $( [23-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.38 of [WhiteheadRussell] p. 105. $)
  pm2.38 $p |-  ( ( ps -> ch ) -> ( ( -. ps -> ph ) -> ( -. ch -> ph ) ) ) $=
    ( wi wn con3 syl4d ) BCDCEBEABCFG $.
    $( [27-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.5 of [WhiteheadRussell] p. 107. $)
  pm2.5 $p |-  ( -. ( ph -> ps ) -> ( -. ph -> ps ) ) $=
    ( wi wn pm2.21 con3i pm2.21d ) ABCZDADZBIHABEFG $.
    $( [27-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.51 of [WhiteheadRussell] p. 107. $)
  pm2.51 $p |-  ( -. ( ph -> ps ) -> ( ph -> -. ps ) ) $=
    ( wi wn ax-1 con3i a1d ) ABCZDBDABHBAEFG $.
    $( [27-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.52 of [WhiteheadRussell] p. 107. $)
  pm2.52 $p |-  ( -. ( ph -> ps ) -> ( -. ph -> -. ps ) ) $=
    ( wi wn ax-1 con3i a1d ) ABCZDBDADBHBAEFG $.
    $( [27-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.521 of [WhiteheadRussell] p. 107. $)
  pm2.521 $p |-  ( -. ( ph -> ps ) -> ( ps -> ph ) ) $=
    ( wi wn pm2.52 a3d ) ABCDABABEF $.
    $( [6-Feb-05] $) $( [3-Jan-05] $)

  ${
    pm2.21ni.1 $e |- ph $.
    $( Inference related to ~ pm2.21 . $)
    pm2.21ni $p |- ( -. ph -> ps ) $=
      ( wn a1i con1i ) BAABDCEF $.
      $( [20-Aug-01] $)
  $}

  ${
    mto.1 $e |- -. ps $.
    mto.2 $e |- ( ph -> ps ) $.
    $( The rule of modus tollens. $)
    mto $p |- -. ph $=
      ( wn con3i ax-mp ) BEAECABDFG $.
      $( [19-Aug-93] $)
  $}

  ${
    mtoi.1 $e |- -. ch $.
    mtoi.2 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Modus tollens inference. $)
    mtoi $p |- ( ph -> -. ps ) $=
      ( wn con3d mpi ) ACFBFDABCEGH $.
      $( [5-Jul-94] $)
  $}

  ${
    mtod.1 $e |- ( ph -> -. ch ) $.
    mtod.2 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Modus tollens deduction. $)
    mtod $p |- ( ph -> -. ps ) $=
      ( wn con3d mpd ) ACFBFDABCEGH $.
      $( [3-Apr-94] $)
  $}

  ${
    mt2.1 $e |- ps $.
    mt2.2 $e |- ( ph -> -. ps ) $.
    $( A rule similar to modus tollens. $)
    mt2 $p |- -. ph $=
      ( wn con2i ax-mp ) BAECABDFG $.
      $( [19-Aug-93] $)
  $}

  ${
    mt2i.1 $e |- ch $.
    mt2i.2 $e |- ( ph -> ( ps -> -. ch ) ) $.
    $( Modus tollens inference. $)
    mt2i $p |- ( ph -> -. ps ) $=
      ( wn con2d mpi ) ACBFDABCEGH $.
      $( [26-Mar-95] $)
  $}

  ${
    mt2d.1 $e |- ( ph -> ch ) $.
    mt2d.2 $e |- ( ph -> ( ps -> -. ch ) ) $.
    $( Modus tollens deduction. $)
    mt2d $p |- ( ph -> -. ps ) $=
      ( wn con2d mpd ) ACBFDABCEGH $.
      $( [4-Jul-94] $)
  $}

  ${
    mt3.1 $e |- -. ps $.
    mt3.2 $e |- ( -. ph -> ps ) $.
    $( A rule similar to modus tollens. $)
    mt3 $p |- ph $=
      ( wn con1i ax-mp ) BEACABDFG $.
      $( [18-May-94] $)
  $}

  ${
    mt3i.1 $e |- -. ch $.
    mt3i.2 $e |- ( ph -> ( -. ps -> ch ) ) $.
    $( Modus tollens inference. $)
    mt3i $p |- ( ph -> ps ) $=
      ( wn con1d mpi ) ACFBDABCEGH $.
      $( [26-Mar-95] $)
  $}

  ${
    mt3d.1 $e |- ( ph -> -. ch ) $.
    mt3d.2 $e |- ( ph -> ( -. ps -> ch ) ) $.
    $( Modus tollens deduction. $)
    mt3d $p |- ( ph -> ps ) $=
      ( wn con1d mpd ) ACFBDABCEGH $.
      $( [26-Mar-95] $)
  $}

  ${
    nsyl.1 $e |- ( ph -> -. ps ) $.
    nsyl.2 $e |- ( ch -> ps ) $.
    $( A negated syllogism inference. $)
    nsyl $p |- ( ph -> -. ch ) $=
      ( wn con3i syl ) ABFCFDCBEGH $.
      $( [31-Dec-93] $)
  $}

  ${
    nsyl2.1 $e |- ( ph -> -. ps ) $.
    nsyl2.2 $e |- ( -. ch -> ps ) $.
    $( A negated syllogism inference. $)
    nsyl2 $p |- ( ph -> ch ) $=
      ( wn con1i syl ) ABFCDCBEGH $.
      $( [26-Jun-94] $)
  $}

  ${
    nsyl3.1 $e |- ( ph -> -. ps ) $.
    nsyl3.2 $e |- ( ch -> ps ) $.
    $( A negated syllogism inference. $)
    nsyl3 $p |- ( ch -> -. ph ) $=
      ( wn con2i syl ) CBAFEABDGH $.
      $( [1-Dec-95] $)
  $}

  ${
    nsyl4.1 $e |- ( ph -> ps ) $.
    nsyl4.2 $e |- ( -. ph -> ch ) $.
    $( A negated syllogism inference. $)
    nsyl4 $p |- ( -. ch -> ps ) $=
      ( wn con1i syl ) CFABACEGDH $.
      $( [15-Feb-96] $)
  $}

  ${
    nsyli.1 $e |- ( ph -> ( ps -> ch ) ) $.
    nsyli.2 $e |- ( th -> -. ch ) $.
    $( A negated syllogism inference. $)
    nsyli $p |- ( ph -> ( th -> -. ps ) ) $=
      ( wn con3d syl5 ) ACGBGDABCEHFI $.
      $( [3-May-94] $)
  $}

  $( Theorem *3.2 of [WhiteheadRussell] p. 111, expressed with primitive
     connectives.    (The proof was shortened by Josh Purinton, 29-Dec-00.) $)
  pm3.2im $p |- ( ph -> ( ps -> -. ( ph -> -. ps ) ) ) $=
    ( wn wi pm2.27 con2d ) AABCZDBAGEF $.
    $( [5-Aug-93] $)

  $( Theorem 8 of [Margaris] p. 60.  (The proof was shortened by Josh Purinton,
     29-Dec-00.) $)
  mth8 $p |- ( ph -> ( -. ps -> -. ( ph -> ps ) ) ) $=
    ( wi pm2.27 con3d ) AABCBABDE $.
    $( [5-Aug-93] $)

  $( Theorem *2.61 of [WhiteheadRussell] p. 107.  Useful for eliminating an
     antecedent. $)
  pm2.61 $p |- ( ( ph -> ps ) -> ( ( -. ph -> ps ) -> ps ) ) $=
    ( wi wn syl1 pm2.18 syl6 con1 syl5 ) ABCZBDZACZBADBCJLKBCBABKEBFGABHI $.
    $( [5-Aug-93] $)

  ${
    pm2.61i.1 $e |- ( ph -> ps ) $.
    pm2.61i.2 $e |- ( -. ph -> ps ) $.
    $( Inference eliminating an antecedent. $)
    pm2.61i $p |- ps $=
      ( wi wn pm2.61 mp2 ) ABEAFBEBCDABGH $.
      $( [5-Apr-94] $)
  $}

  ${
    pm2.61d2.1 $e |- ( ph -> ( -. ps -> ch ) ) $.
    pm2.61d2.2 $e |- ( ps -> ch ) $.
    $( Inference eliminating an antecedent. $)
    pm2.61d2 $p |- ( ph -> ch ) $=
      ( wi a1d wn com12 pm2.61i ) BACFBCAEGABHCDIJ $.
      $( [18-Aug-93] $)
  $}

  ${
    pm2.61d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    pm2.61d.2 $e |- ( ph -> ( -. ps -> ch ) ) $.
    $( Deduction eliminating an antecedent. $)
    pm2.61d $p |- ( ph -> ch ) $=
      ( wi com12 wn pm2.61i ) BACFABCDGABHCEGI $.
      $( [27-Apr-94] $)
  $}

  ${
    pm2.61ii.1 $e |- ( -. ph -> ( -. ps -> ch ) ) $.
    pm2.61ii.2 $e |- ( ph -> ch ) $.
    pm2.61ii.3 $e |- ( ps -> ch ) $.
    $( Inference eliminating two antecedents.  (The proof was shortened by Josh
       Purinton,  29-Dec-00.) $)
    pm2.61ii $p |- ch $=
      ( wn pm2.61d2 pm2.61i ) ACEAGBCDFHI $.
      $( [5-Aug-93] $)
  $}

  ${
    pm2.61iii.1 $e |- ( -. ph -> ( -. ps -> ( -. ch -> th ) ) ) $.
    pm2.61iii.2 $e |- ( ph -> th ) $.
    pm2.61iii.3 $e |- ( ps -> th ) $.
    pm2.61iii.4 $e |- ( ch -> th ) $.
    $( Inference eliminating three antecedents. $)
    pm2.61iii $p |- th $=
      ( wn wi a1d pm2.61i pm2.61ii ) BCDABIZCIZDJZJAPNADOFKKELGHM $.
      $( [2-Jan-02] $)
  $}

  $( Theorem *2.6 of [WhiteheadRussell] p. 107. $)
  pm2.6 $p |-  ( ( -. ph -> ps ) -> ( ( ph -> ps ) -> ps ) ) $=
    ( wi wn pm2.61 com12 ) ABCADBCBABEF $.
    $( [1-Feb-05] $) $( [3-Jan-05] $)

  $( Theorem *2.65 of [WhiteheadRussell] p. 107.  Useful for eliminating a
     consequent. $)
  pm2.65 $p |- ( ( ph -> ps ) -> ( ( ph -> -. ps ) -> -. ph ) ) $=
    ( wi wn pm3.2im a2i con2d ) ABCAABDCZABHDABEFG $.
    $( [5-Aug-93] $)

  ${
    pm2.65i.1 $e |- ( ph -> ps ) $.
    pm2.65i.2 $e |- ( ph -> -. ps ) $.
    $( Inference rule for proof by contradiction. $)
    pm2.65i $p |- -. ph $=
      ( wn wi nsyl pm2.01 ax-mp ) AAEZFJABADCGAHI $.
      $( [18-May-94] $)
  $}

  ${
    pm2.65d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    pm2.65d.2 $e |- ( ph -> ( ps -> -. ch ) ) $.
    $( Deduction rule for proof by contradiction. $)
    pm2.65d $p |- ( ph -> -. ps ) $=
      ( wi wn pm2.65 sylc ) BCFBCGFBGABCHDEI $.
      $( [26-Jun-94] $)
  $}

  ${
    ja.1 $e |- ( -. ph -> ch ) $.
    ja.2 $e |- ( ps -> ch ) $.
    $( Inference joining the antecedents of two premises.  (The proof was
       shortened by Mel L. O'Cat, 30-Aug-04.) $)
    ja $p |- ( ( ph -> ps ) -> ch ) $=
      ( wi pm2.27 syl6 wn a1d pm2.61i ) AABFZCFALBCABGEHAICLDJK $.
      $( [31-Aug-04] $) $( [5-Aug-93] $)
  $}

  ${
    jc.1 $e |- ( ph -> ps ) $.
    jc.2 $e |- ( ph -> ch ) $.
    $( Inference joining the consequents of two premises. $)
    jc $p |- ( ph -> -. ( ps -> -. ch ) ) $=
      ( wn wi pm3.2im sylc ) BCBCFGFABCHDEI $.
      $( [5-Aug-93] $)
  $}

  $( Simplification.  Similar to Theorem *3.26 of [WhiteheadRussell] p. 112. $)
  pm3.26im $p |- ( -. ( ph -> -. ps ) -> ph ) $=
    ( wn wi pm2.21 con1i ) AABCZDAGEF $.
    $( [5-Aug-93] $)

  $( Simplification.  Similar to Theorem *3.27 of [WhiteheadRussell] p. 112. $)
  pm3.27im $p |- ( -. ( ph -> -. ps ) -> ps ) $=
    ( wn wi ax-1 con1i ) BABCZDGAEF $.
    $( [5-Aug-93] $)

  $( Importation theorem expressed with primitive connectives. $)
  impt $p |- ( ( ph -> ( ps -> ch ) ) -> ( -. ( ph -> -. ps ) -> ch ) ) $=
    ( wi wn con3 syl3 com23 con1d ) ABCDZDZCABEZDKACEZLJMLDABCFGHI $.
    $( [25-Apr-94] $)

  $( Exportation theorem expressed with primitive connectives. $)
  expt $p |- ( ( -. ( ph -> -. ps ) -> ch ) -> ( ph -> ( ps -> ch ) ) ) $=
    ( wn wi pm3.2im syl4d com12 ) AABDEDZCEBCEABICABFGH $.
    $( [5-Aug-93] $)

  ${
    impi.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( An importation inference. $)
    impi $p |- ( -. ( ph -> -. ps ) -> ch ) $=
      ( wi wn impt ax-mp ) ABCEEABFEFCEDABCGH $.
      $( [5-Aug-93] $)
  $}

  ${
    expi.1 $e |- ( -. ( ph -> -. ps ) -> ch ) $.
    $( An exportation inference. $)
    expi $p |- ( ph -> ( ps -> ch ) ) $=
      ( wn wi expt ax-mp ) ABEFECFABCFFDABCGH $.
      $( [5-Aug-93] $)
  $}

  $( Theorem used to justify definition of biconditional ~ df-bi .  (The proof
     was shortened by Josh Purinton, 29-Dec-00.) $)
  bijust $p |- -. ( ( ph -> ph ) -> -. ( ph -> ph ) ) $=
    ( wi wn id pm2.01 mt2 ) AABZGCBGADGEF $.
    $( [11-May-99] $)

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Logical equivalence
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( Declare the biconditional connective. $)
  $c <-> $. $( Double arrow (read:  'if and only if' or
               'is logically equivalent to') $)

  $( Extend our wff definition to include the biconditional connective. $)
  wb $a wff ( ph <-> ps ) $.

  $( This is our first definition, which introduces and defines the
     biconditional connective ` <-> ` . Unlike most traditional developments,
     we have chosen not to have a separate symbol such as 'Df.' to mean 'is
     defined as.'  Instead, we will later use the biconditional connective
     for this purpose, as it allows us to use logic to manipulate definitions
     directly ( ~ df-or is its first use).  Here we use the biconditional
     connective to define itself, a feat which requires a little care.  We
     define ` ( ph <-> ps ) ` as ` -. ( ( ph -> ps ) -> -. ( ps -> ph ) ) `
     but we don't yet have a notation that can express this directly, so we
     use a more complicated expression using the language that we have so
     far.  The justification for our definition is that if we mechanically
     substitute the second wff for the first in the definition, the
     definition becomes an instance of previously proved theorem ~ bijust .
     Note that from Metamath's point of view, a definition is just another
     axiom; but from our high level point of view, we are are not
     strengthening the language since if we mechanically eliminate the new
     symbol ` <-> ` we will not end up with any theorems we could not prove
     before.  To indicate this fact we prefix definition labels with "df-"
     instead of "ax-".  (This prefixing is an informal convention that means
     nothing to the Metamath proof verifier; it is just for human
     readability.)  See ~ bii and ~ bi for theorems suggesting the typical
     textbook definition of ` <-> ` . $)
  df-bi $a |- -. ( ( ( ph <-> ps ) -> -. ( ( ph -> ps ) -> -. ( ps -> ph ) ) )
        -> -. ( -. ( ( ph -> ps ) -> -. ( ps -> ph ) ) -> ( ph <-> ps ) ) ) $.

  $( This proof of ~ bii , discovered by Gregory Bush on 8-Mar-04, has
     several curious properties.  First, it has only 17 steps directly
     from the axioms and ~ df-bi , compared to over 800 steps were the proof
     of ~ bii expanded into axioms.  Second, step 2 demands only the property
     of "true"; any axiom (or theorem) could be used.  Third, it illustrates
     how intermediate steps can "blow up" in size even in short proofs.
     Fourth, the compressed proof is only 2.5 lines long, but the web page
     is over 200kB in size.  If there were an obfuscated code contest for
     proofs, this might be a winner. $)
  biigb $p |- ( ( ph <-> ps ) <-> -. ( ( ph -> ps ) -> -. ( ps -> ph ) ) ) $=
    ( wch wth wb wi wn df-bi ax-1 ax-mp ax-3 ax-2 ) ABEZABFBAFGFGZFNMFGFGZMNEZA
    BHCDCFFZOPFZCDIRGZQGZFZQRFSPOFZSFZFZUASUBISUCTFZFZUDUAFUEUFTGZUCGZFZUEUHUIM
    NHUHUGIJTUCKJUESIJSUCTLJJRQKJJJ $.
    $( [10-Mar-04] $) $( [10-Mar-04] $)

  $( Property of the biconditional connective. $)
  bi1 $p |- ( ( ph <-> ps ) -> ( ph -> ps ) ) $=
    ( wb wi wn df-bi pm3.26im ax-mp syl ) ABCZABDZBADZEDEZKJMDZMJDZEDENABFNOGHK
    LGI $.
    $( [11-May-99] $)

  $( Property of the biconditional connective. $)
  bi2 $p |- ( ( ph <-> ps ) -> ( ps -> ph ) ) $=
    ( wb wi wn df-bi pm3.26im ax-mp pm3.27im syl ) ABCZABDZBADZEDEZMKNDZNKDZEDE
    OABFOPGHLMIJ $.
    $( [11-May-99] $)

  $( Property of the biconditional connective. $)
  bi3 $p |- ( ( ph -> ps ) -> ( ( ps -> ph ) -> ( ph <-> ps ) ) ) $=
    ( wi wb wn df-bi pm3.27im ax-mp expi ) ABCZBACZABDZLJKECEZCZMLCZECEOABFNOGH
    I $.
    $( [11-May-99] $)

  ${
    biimp.1 $e |- ( ph <-> ps ) $.
    $( Infer an implication from a logical equivalence. $)
    biimp $p |- ( ph -> ps ) $=
      ( wb wi bi1 ax-mp ) ABDABECABFG $.
      $( [5-Aug-93] $)
  $}

  ${
    biimpr.1 $e |- ( ph <-> ps ) $.
    $( Infer a converse implication from a logical equivalence. $)
    biimpr $p |- ( ps -> ph ) $=
      ( wb wi bi2 ax-mp ) ABDBAECABFG $.
      $( [5-Aug-93] $)
  $}

  ${
    biimpd.1 $e |- ( ph -> ( ps <-> ch ) ) $.

    $( Deduce an implication from a logical equivalence. $)
    biimpd $p |- ( ph -> ( ps -> ch ) ) $=
      ( wb wi bi1 syl ) ABCEBCFDBCGH $.
      $( [5-Aug-93] $)

   $( Deduce a converse implication from a logical equivalence. $)
    biimprd $p |- ( ph -> ( ch -> ps ) ) $=
      ( wb wi bi2 syl ) ABCECBFDBCGH $.
      $( [5-Aug-93] $)

   $( Deduce a commuted implication from a logical equivalence. $)
    biimpcd $p |- ( ps -> ( ph -> ch ) ) $=
      ( biimpd com12 ) ABCABCDEF $.
      $( [3-May-94] $)

   $( Deduce a converse commuted implication from a logical equivalence. $)
    biimprcd $p |- ( ch -> ( ph -> ps ) ) $=
      ( biimprd com12 ) ACBABCDEF $.
      $( [3-May-94] $)
  $}

  ${
    impbi.1 $e |- ( ph -> ps ) $.
    impbi.2 $e |- ( ps -> ph ) $.
    $( Infer an equivalence from an implication and its converse. $)
    impbi $p |- ( ph <-> ps ) $=
      ( wi wb bi3 mp2 ) ABEBAEABFCDABGH $.
      $( [5-Aug-93] $)
  $}

  $( Relate the biconditional connective to primitive connectives.  See ~ biigb
     for an unusual version proved directly from axioms. $)
  bii $p |- ( ( ph <-> ps ) <-> -. ( ( ph -> ps ) -> -. ( ps -> ph ) ) ) $=
    ( wb wi wn bi1 bi2 jc bi3 impi impbi ) ABCZABDZBADZEDELMNABFABGHMNLABIJK $.
    $( [5-Aug-93] $)

  $( Logical equivalence of commuted antecedents.  Part of Theorem *4.87 of
     [WhiteheadRussell] p. 122. $)
  bi2.04 $p |- ( ( ph -> ( ps -> ch ) ) <-> ( ps -> ( ph -> ch ) ) ) $=
    ( wi pm2.04 impbi ) ABCDDBACDDABCEBACEF $.
    $( [5-Aug-93] $)

  $( Double negation.  Theorem *4.13 of [WhiteheadRussell] p. 117. $)
  pm4.13 $p |- ( ph <-> -. -. ph ) $=
    ( wn negb nega impbi ) AABBACADE $.
    $( [5-Aug-93] $)

  $( Theorem *4.8 of [WhiteheadRussell] p. 122. $)
  pm4.8 $p |-  ( ( ph -> -. ph ) <-> -. ph ) $=
    ( wn wi pm2.01 ax-1 impbi ) AABZCGADGAEF $.
    $( [5-Feb-05] $) $( [3-Jan-05] $)

  $( Theorem *4.81 of [WhiteheadRussell] p. 122. $)
  pm4.81 $p |-  ( ( -. ph -> ph ) <-> ph ) $=
    ( wn wi pm2.18 pm2.24 impbi ) ABACAADAAEF $.
    $( [10-Feb-05] $) $( [3-Jan-05] $)

  $( Contraposition.  Theorem *4.1 of [WhiteheadRussell] p. 116. $)
  pm4.1 $p |- ( ( ph -> ps ) <-> ( -. ps -> -. ph ) ) $=
    ( wi wn con3 ax-3 impbi ) ABCBDADCABEBAFG $.
    $( [5-Aug-93] $)

  $( Contraposition.  Bidirectional version of ~ con2 . $)
  bi2.03 $p |- ( ( ph -> -. ps ) <-> ( ps -> -. ph ) ) $=
    ( wn wi con2 impbi ) ABCDBACDABEBAEF $.
    $( [5-Aug-93] $)

  $( Contraposition.  Bidirectional version of ~ con1 . $)
  bi2.15 $p |- ( ( -. ph -> ps ) <-> ( -. ps -> ph ) ) $=
    ( wn wi con1 impbi ) ACBDBCADABEBAEF $.
    $( [5-Aug-93] $)

  $( Antecedent absorption implication.  Theorem *5.4 of
     [WhiteheadRussell] p. 125. $)
  pm5.4 $p |- ( ( ph -> ( ph -> ps ) ) <-> ( ph -> ps ) ) $=
    ( wi pm2.43 ax-1 impbi ) AABCZCGABDGAEF $.
    $( [5-Aug-93] $)

  $( Distributive law for implication.  Compare Theorem *5.41 of
     [WhiteheadRussell] p. 125. $)
  imdi $p |- ( ( ph -> ( ps -> ch ) ) <->
               ( ( ph -> ps ) -> ( ph -> ch ) ) ) $=
    ( wi ax-2 pm2.86 impbi ) ABCDDABDACDDABCEABCFG $.
    $( [5-Aug-93] $)

  $( Theorem *5.41 of [WhiteheadRussell] p. 125. $)
  pm5.41 $p |-  ( ( ( ph -> ps ) -> ( ph -> ch ) ) <->
                ( ph -> ( ps -> ch ) ) ) $=
    ( wi pm2.86 ax-2 impbi ) ABDACDDABCDDABCEABCFG $.
    $( [10-Feb-05] $) $( [3-Jan-05] $)

  $( Principle of identity for logical equivalence.  Theorem *4.2 of
     [WhiteheadRussell] p. 117. $)
  pm4.2 $p |- ( ph <-> ph ) $=
    ( id impbi ) AAABZDC $.
    $( [5-Aug-93] $)

  $( Principle of identity with antecedent. $)
  pm4.2i $p |- ( ph -> ( ps <-> ps ) ) $=
    ( wb pm4.2 a1i ) BBCABDE $.
    $( [25-Nov-95] $)

  ${
    bicom.1 $e |- ( ph <-> ps ) $.
    $( Inference from commutative law for logical equivalence. $)
    bicomi $p |- ( ps <-> ph ) $=
      ( biimpr biimp impbi ) BAABCDABCEF $.
      $( [5-Aug-93] $)
  $}

  ${
    bitr.1 $e |- ( ph <-> ps ) $.
    bitr.2 $e |- ( ps <-> ch ) $.
    $( An inference from transitive law for logical equivalence. $)
    bitr $p |- ( ph <-> ch ) $=
      ( biimp syl biimpr impbi ) ACABCABDFBCEFGCBABCEHABDHGI $.
      $( [5-Aug-93] $)
  $}

  ${
    bitr2.1 $e |- ( ph <-> ps ) $.
    bitr2.2 $e |- ( ps <-> ch ) $.
    $( An inference from transitive law for logical equivalence. $)
    bitr2 $p |- ( ch <-> ph ) $=
      ( bitr bicomi ) ACABCDEFG $.
      $( [5-Aug-93] $)
  $}

  ${
    bitr3.1 $e |- ( ps <-> ph ) $.
    bitr3.2 $e |- ( ps <-> ch ) $.
    $( An inference from transitive law for logical equivalence. $)
    bitr3 $p |- ( ph <-> ch ) $=
      ( bicomi bitr ) ABCBADFEG $.
      $( [5-Aug-93] $)
  $}

  ${
    bitr4.1 $e |- ( ph <-> ps ) $.
    bitr4.2 $e |- ( ch <-> ps ) $.
    $( An inference from transitive law for logical equivalence. $)
    bitr4 $p |- ( ph <-> ch ) $=
      ( bicomi bitr ) ABCDCBEFG $.
      $( [5-Aug-93] $)
  $}

  ${
    3bitr.1 $e |- ( ph <-> ps ) $.
    3bitr.2 $e |- ( ps <-> ch ) $.
    3bitr.3 $e |- ( ch <-> th ) $.
    $( A chained inference from transitive law for logical equivalence. $)
    3bitr $p |- ( ph <-> th ) $=
      ( bitr ) ABDEBCDFGHH $.
      $( [5-Aug-93] $)
  $}

  ${
    3bitr3.1 $e |- ( ph <-> ps ) $.
    3bitr3.2 $e |- ( ph <-> ch ) $.
    3bitr3.3 $e |- ( ps <-> th ) $.
    $( A chained inference from transitive law for logical equivalence. $)
    3bitr3 $p |- ( ch <-> th ) $=
      ( bitr3 bitr ) CBDCABFEHGI $.
      $( [19-Aug-93] $)

    $( A chained inference from transitive law for logical equivalence. $)
    3bitr3r $p |- ( th <-> ch ) $=
      ( bitr3 ) DBCGBACEFHH $.
      $( [5-Aug-93] $)
  $}

  ${
    3bitr4.1 $e |- ( ph <-> ps ) $.
    3bitr4.2 $e |- ( ch <-> ph ) $.
    3bitr4.3 $e |- ( th <-> ps ) $.
    $( A chained inference from transitive law for logical equivalence.  This
       inference is frequently used to apply a definition to both sides of a
       logical equivalence. $)
    3bitr4 $p |- ( ch <-> th ) $=
      ( bitr4 bitr ) CADFABDEGHI $.
      $( [5-Aug-93] $)

    $( A chained inference from transitive law for logical equivalence. $)
    3bitr4r $p |- ( th <-> ch ) $=
      ( bitr4 bitr2 ) CADFABDEGHI $.
      $( [2-Sep-95] $)
  $}

  $( The next three rules are useful for building up wff's around a
     definition, in order to make use of the definition. $)

  ${
    bi.a $e |- ( ph <-> ps ) $.

    $( Introduce an antecedent to both sides of a logical equivalence. $)
    imbi2i $p |- ( ( ch -> ph ) <-> ( ch -> ps ) ) $=
      ( wi biimp syl3 biimpr impbi ) CAECBEABCABDFGBACABDHGI $.
      $( [5-Aug-93] $)

    $( Introduce a consequent to both sides of a logical equivalence. $)
    imbi1i $p |- ( ( ph -> ch ) <-> ( ps -> ch ) ) $=
      ( wi biimpr syl4 biimp impbi ) ACEBCEBACABDFGABCABDHGI $.
      $( [5-Aug-93] $)

    $( Negate both sides of a logical equivalence. $)
    negbii $p |- ( -. ph <-> -. ps ) $=
      ( wn biimpr con3i biimp impbi ) ADBDBAABCEFABABCGFH $.
      $( [5-Aug-93] $)

  $}

  ${
    bi2im.1 $e |- ( ph <-> ps ) $.
    bi2im.2 $e |- ( ch <-> th ) $.
    $( Join two logical equivalences to form equivalence of implications. $)
    imbi12i $p |- ( ( ph -> ch ) <-> ( ps -> th ) ) $=
      ( wi imbi2i imbi1i bitr ) ACGADGBDGCDAFHABDEIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    mpbi.min $e |- ph $.
    mpbi.maj $e |- ( ph <-> ps ) $.
    $( An inference from a biconditional, related to modus ponens. $)
    mpbi $p |- ps $=
      ( biimp ax-mp ) ABCABDEF $.
      $( [5-Aug-93] $)
  $}

  ${
    mpbir.min $e |- ps $.
    mpbir.maj $e |- ( ph <-> ps ) $.
    $( An inference from a biconditional, related to modus ponens. $)
    mpbir $p |- ph $=
      ( biimpr ax-mp ) BACABDEF $.
      $( [5-Aug-93] $)
  $}

  ${
    mtbi.1 $e |- -. ph $.
    mtbi.2 $e |- ( ph <-> ps ) $.
    $( An inference from a biconditional, related to modus tollens. $)
    mtbi $p |- -. ps $=
      ( wn negbii mpbi ) AEBECABDFG $.
      $( [15-Nov-94] $)
  $}

  ${
    mtbir.1 $e |- -. ps $.
    mtbir.2 $e |- ( ph <-> ps ) $.
    $( An inference from a biconditional, related to modus tollens. $)
    mtbir $p |- -. ph $=
      ( wn negbii mpbir ) AEBECABDFG $.
      $( [15-Nov-94] $)
  $}

  ${
    mpbii.min $e |- ps $.
    mpbii.maj $e |- ( ph -> ( ps <-> ch ) ) $.
    $( An inference from a nested biconditional, related to modus ponens. $)
    mpbii $p |- ( ph -> ch ) $=
      ( biimpd mpi ) ABCDABCEFG $.
      $( [5-Aug-93] $)
  $}

  ${
    mpbiri.min $e |- ch $.
    mpbiri.maj $e |- ( ph -> ( ps <-> ch ) ) $.
    $( An inference from a nested biconditional, related to modus ponens. $)
    mpbiri $p |- ( ph -> ps ) $=
      ( biimprd mpi ) ACBDABCEFG $.
      $( [5-Aug-93] $)
  $}

  ${
    mpbid.min $e |- ( ph -> ps ) $.
    mpbid.maj $e |- ( ph -> ( ps <-> ch ) ) $.
    $( A deduction from a biconditional, related to modus ponens. $)
    mpbid $p |- ( ph -> ch ) $=
      ( biimpd mpd ) ABCDABCEFG $.
      $( [5-Aug-93] $)
  $}

  ${
    mpbird.min $e |- ( ph -> ch ) $.
    mpbird.maj $e |- ( ph -> ( ps <-> ch ) ) $.
    $( A deduction from a biconditional, related to modus ponens. $)
    mpbird $p |- ( ph -> ps ) $=
      ( biimprd mpd ) ACBDABCEFG $.
      $( [5-Aug-93] $)
  $}

  ${
    a1bi.1 $e |- ph $.
    $( Inference rule introducing a theorem as an antecedent. $)
    a1bi $p |- ( ps <-> ( ph -> ps ) ) $=
      ( wi ax-1 pm2.27 ax-mp impbi ) BABDZBAEAIBDCABFGH $.
      $( [5-Aug-93] $)
  $}

  ${
    sylib.1 $e |- ( ph -> ps ) $.
    sylib.2 $e |- ( ps <-> ch ) $.
    $( A mixed syllogism inference from an implication and a biconditional. $)
    sylib $p |- ( ph -> ch ) $=
      ( biimp syl ) ABCDBCEFG $.
      $( [5-Aug-93] $)
  $}

  ${
    sylbi.1 $e |- ( ph <-> ps ) $.
    sylbi.2 $e |- ( ps -> ch ) $.
    $( A mixed syllogism inference from a biconditional and an implication.
       Useful for substituting an antecedent with a definition. $)
    sylbi $p |- ( ph -> ch ) $=
      ( biimp syl ) ABCABDFEG $.
      $( [5-Aug-93] $)
  $}

  ${
    sylibr.1 $e |- ( ph -> ps ) $.
    sylibr.2 $e |- ( ch <-> ps ) $.
    $( A mixed syllogism inference from an implication and a biconditional.
       Useful for substituting a consequent with a definition. $)
    sylibr $p |- ( ph -> ch ) $=
      ( biimpr syl ) ABCDCBEFG $.
      $( [5-Aug-93] $)
  $}

  ${
    sylbir.1 $e |- ( ps <-> ph ) $.
    sylbir.2 $e |- ( ps -> ch ) $.
    $( A mixed syllogism inference from a biconditional and an implication. $)
    sylbir $p |- ( ph -> ch ) $=
      ( biimpr syl ) ABCBADFEG $.
      $( [5-Aug-93] $)
  $}

  ${
    sylibd.1 $e |- ( ph -> ( ps -> ch ) ) $.
    sylibd.2 $e |- ( ph -> ( ch <-> th ) ) $.
    $( A syllogism deduction. $)
    sylibd $p |- ( ph -> ( ps -> th ) ) $=
      ( biimpd syld ) ABCDEACDFGH $.
      $( [3-Aug-94] $)
  $}

  ${
    sylbid.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    sylbid.2 $e |- ( ph -> ( ch -> th ) ) $.
    $( A syllogism deduction. $)
    sylbid $p |- ( ph -> ( ps -> th ) ) $=
      ( biimpd syld ) ABCDABCEGFH $.
      $( [3-Aug-94] $)
  $}

  ${
    sylibrd.1 $e |- ( ph -> ( ps -> ch ) ) $.
    sylibrd.2 $e |- ( ph -> ( th <-> ch ) ) $.
    $( A syllogism deduction. $)
    sylibrd $p |- ( ph -> ( ps -> th ) ) $=
      ( biimprd syld ) ABCDEADCFGH $.
      $( [3-Aug-94] $)
  $}

  ${
    sylbird.1 $e |- ( ph -> ( ch <-> ps ) ) $.
    sylbird.2 $e |- ( ph -> ( ch -> th ) ) $.
    $( A syllogism deduction. $)
    sylbird $p |- ( ph -> ( ps -> th ) ) $=
      ( biimprd syld ) ABCDACBEGFH $.
      $( [3-Aug-94] $)
  $}

  ${
    syl5ib.1 $e |- ( ph -> ( ps -> ch ) ) $.
    syl5ib.2 $e |- ( th <-> ps ) $.
    $( A mixed syllogism inference from a nested implication and a
       biconditional.  Useful for substituting an embedded antecedent with a
       definition. $)
    syl5ib $p |- ( ph -> ( th -> ch ) ) $=
      ( biimp syl5 ) ABCDEDBFGH $.
      $( [5-Aug-93] $)
  $}

  ${
    syl5ibr.1 $e |- ( ph -> ( ps -> ch ) ) $.
    syl5ibr.2 $e |- ( ps <-> th ) $.
    $( A mixed syllogism inference from a nested implication and a
       biconditional. $)
    syl5ibr $p |- ( ph -> ( th -> ch ) ) $=
      ( biimpr syl5 ) ABCDEBDFGH $.
      $( [5-Aug-93] $)
  $}

  ${
    syl5bi.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl5bi.2 $e |- ( th -> ps ) $.
    $( A mixed syllogism inference. $)
    syl5bi $p |- ( ph -> ( th -> ch ) ) $=
      ( biimpd syl5 ) ABCDABCEGFH $.
      $( [5-Aug-93] $)
  $}

  ${
    syl5bir.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl5bir.2 $e |- ( th -> ch ) $.
    $( A mixed syllogism inference. $)
    syl5bir $p |- ( ph -> ( th -> ps ) ) $=
      ( biimprd syl5 ) ACBDABCEGFH $.
      $( [3-Apr-94] $)
  $}

  ${
    syl6ib.1 $e |- ( ph -> ( ps -> ch ) ) $.
    syl6ib.2 $e |- ( ch <-> th ) $.
    $( A mixed syllogism inference from a nested implication and a
       biconditional. $)
    syl6ib $p |- ( ph -> ( ps -> th ) ) $=
      ( biimp syl6 ) ABCDECDFGH $.
      $( [5-Aug-93] $)
  $}

  ${
    syl6ibr.1 $e |- ( ph -> ( ps -> ch ) ) $.
    syl6ibr.2 $e |- ( th <-> ch ) $.
    $( A mixed syllogism inference from a nested implication and a
       biconditional.  Useful for substituting an embedded consequent with a
       definition. $)
    syl6ibr $p |- ( ph -> ( ps -> th ) ) $=
      ( biimpr syl6 ) ABCDEDCFGH $.
      $( [5-Aug-93] $)
  $}


  ${
    syl6bi.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl6bi.2 $e |- ( ch -> th ) $.
    $( A mixed syllogism inference. $)
    syl6bi $p |- ( ph -> ( ps -> th ) ) $=
      ( biimpd syl6 ) ABCDABCEGFH $.
      $( [2-Jan-94] $)
  $}

  ${
    syl6bir.1 $e |- ( ph -> ( ch <-> ps ) ) $.
    syl6bir.2 $e |- ( ch -> th ) $.
    $( A mixed syllogism inference. $)
    syl6bir $p |- ( ph -> ( ps -> th ) ) $=
      ( biimprd syl6 ) ABCDACBEGFH $.
      $( [18-May-94] $)
  $}

  ${
    bisyl7.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    bisyl7.2 $e |- ( ta <-> ch ) $.
    $( A mixed syllogism inference from a doubly nested implication and a
       biconditional. $)
    bisyl7 $p |- ( ph -> ( ps -> ( ta -> th ) ) ) $=
      ( biimp syl7 ) ABCDEFECGHI $.
      $( [5-Aug-93] $)
  $}

  ${
    bisyl8.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    bisyl8.2 $e |- ( th <-> ta ) $.
    $( A syllogism rule of inference.  The second premise is used to replace
       the consequent of the first premise. $)
    bisyl8 $p |- ( ph -> ( ps -> ( ch -> ta ) ) ) $=
      ( biimp syl8 ) ABCDEFDEGHI $.
      $( [1-Aug-94] $)
  $}

  ${
    3imtr3.1 $e |- ( ph -> ps ) $.
    3imtr3.2 $e |- ( ph <-> ch ) $.
    3imtr3.3 $e |- ( ps <-> th ) $.
    $( A mixed syllogism inference, useful for removing a definition from both
       sides of an implication. $)
    3imtr3 $p |- ( ch -> th ) $=
      ( sylbir sylib ) CBDCABFEHGI $.
      $( [10-Aug-94] $)
  $}

  ${
    3imtr4.1 $e |- ( ph -> ps ) $.
    3imtr4.2 $e |- ( ch <-> ph ) $.
    3imtr4.3 $e |- ( th <-> ps ) $.
    $( A mixed syllogism inference, useful for applying a definition to both
       sides of an implication. $)
    3imtr4 $p |- ( ch -> th ) $=
      ( sylbi sylibr ) CBDCABFEHGI $.
      $( [5-Aug-93] $)
  $}

  ${
    bicon1.1 $e |- ( -. ph <-> ps ) $.
    $( A contraposition inference. $)
    bicon1i $p |- ( -. ps <-> ph ) $=
      ( wn biimp con1i biimpr con2i impbi ) BDAABADZBCEFBAJBCGHI $.
      $( [5-Aug-93] $)
  $}

  ${
    bicon2.1 $e |- ( ph <-> -. ps ) $.
    $( A contraposition inference. $)
    bicon2i $p |- ( ps <-> -. ph ) $=
      ( wn bicomi bicon1i ) ADBBAABDCEFE $.
      $( [5-Aug-93] $)
  $}

  $( For ~ bicon3 :  See ~ negbii . $)

  $( For ~ bicon4i :  Later. $)


$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Logical disjunction and conjunction
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( Declare connectives for disjunction ('or') and conjunction ('and'). $)
  $c \/ $. $( Vee (read:  'or') $)
  $c /\ $. $( Wedge (read:  'and') $)

  $( Extend wff definition to include disjunction ('or'). $)
  wo $a wff ( ph \/ ps ) $.
  $( Extend wff definition to include conjunction ('and'). $)
  wa $a wff ( ph /\ ps ) $.

  $( Define disjunction (logical 'or').  This is our first use of the
     biconditional connective in a definition; we use it in place of the
     traditional "<=def=>", which means the same thing, except that we can
     manipulate the biconditional connective directly in proofs rather than
     having to rely on an informal definition substitution rule.  Note that
     if we mechanically substitute ` ( -. ph -> ps ) ` for ` ( ph \/ ps ) ` ,
     we end up with an instance of previously proved theorem ~ pm4.2 . This
     is the justification for the definition, along with the fact that it
     introduces a new symbol ` \/ ` .  Definition of [Margaris] p. 49. $)
  df-or $a |- ( ( ph \/ ps ) <-> ( -. ph -> ps ) ) $.

  $( Define conjunction (logical 'and').  Definition of [Margaris] p. 49. $)
  df-an $a |- ( ( ph /\ ps ) <-> -. ( ph -> -. ps ) ) $.

  $( Theorem *4.64 of [WhiteheadRussell] p. 120. $)
  pm4.64 $p |-  ( ( -. ph -> ps ) <-> ( ph \/ ps ) ) $=
    ( wo wn wi df-or bicomi ) ABCADBEABFG $.
    $( [1-Feb-05] $) $( [3-Jan-05] $)

  $( Theorem *2.54 of [WhiteheadRussell] p. 107. $)
  pm2.54 $p |-  ( ( -. ph -> ps ) -> ( ph \/ ps ) ) $=
    ( wo wn wi df-or biimpr ) ABCADBEABFG $.
    $( [10-Feb-05] $) $( [3-Jan-05] $)

  $( Theorem *4.63 of [WhiteheadRussell] p. 120. $)
  pm4.63 $p |-  ( -. ( ph -> -. ps ) <-> ( ph /\ ps ) ) $=
    ( wa wn wi df-an bicomi ) ABCABDEDABFG $.
    $( [19-Feb-05] $) $( [3-Jan-05] $)

  $( Logical 'or' expressed in terms of implication only.  Theorem *5.25 of
     [WhiteheadRussell] p. 124. $)
  dfor2 $p |- ( ( ph \/ ps ) <-> ( ( ph -> ps ) -> ps ) ) $=
    ( wo wn wi df-or pm2.6 pm2.21 syl4 impbi bitr ) ABCADZBEZABEZBEZABFMOABGLNB
    ABHIJK $.
    $( [20-Aug-04] $) $( [12-Aug-04] $)

  ${
    ori.1 $e |- ( ph \/ ps ) $.
    $( Inference from disjunction definition. $)
    ori $p |- ( -. ph -> ps ) $=
      ( wo wn wi df-or mpbi ) ABDAEBFCABGH $.
      $( [11-Jun-94] $)
  $}

  ${
    orri.1 $e |- ( -. ph -> ps ) $.
    $( Inference from disjunction definition. $)
    orri $p |- ( ph \/ ps ) $=
      ( wo wn wi df-or mpbir ) ABDAEBFCABGH $.
      $( [11-Jun-94] $)
  $}

  ${
    ord.1 $e |- ( ph -> ( ps \/ ch ) ) $.
    $( Deduction from disjunction definition. $)
    ord $p |- ( ph -> ( -. ps -> ch ) ) $=
      ( wo wn wi df-or sylib ) ABCEBFCGDBCHI $.
      $( [18-May-94] $)
  $}

  ${
    orrd.1 $e |- ( ph -> ( -. ps -> ch ) ) $.
    $( Deduction from disjunction definition. $)
    orrd $p |- ( ph -> ( ps \/ ch ) ) $=
      ( wn wi wo df-or sylibr ) ABECFBCGDBCHI $.
      $( [27-Nov-95] $)
  $}

  $( Implication in terms of disjunction.  Theorem *4.6 of
     [WhiteheadRussell] p. 120. $)
  imor $p |- ( ( ph -> ps ) <-> ( -. ph \/ ps ) ) $=
    ( wi wn wo pm4.13 imbi1i df-or bitr4 ) ABCADZDZBCJBEAKBAFGJBHI $.
    $( [5-Aug-93] $)

  $( Theorem *4.62 of [WhiteheadRussell] p. 120. $)
  pm4.62 $p |-  ( ( ph -> -. ps ) <-> ( -. ph \/ -. ps ) ) $=
    ( wn imor ) ABCD $.
    $( [24-Feb-05] $) $( [3-Jan-05] $)

  $( Theorem *4.66 of [WhiteheadRussell] p. 120. $)
  pm4.66 $p |-  ( ( -. ph -> -. ps ) <-> ( ph \/ -. ps ) ) $=
    ( wn pm4.64 ) ABCD $.
    $( [1-Feb-05] $) $( [3-Jan-05] $)

  $( Express implication in terms of conjunction.  Theorem 3.4(27) of [Stoll]
     p. 176. $)
  iman $p |- ( ( ph -> ps ) <-> -. ( ph /\ -. ps ) ) $=
    ( wi wn wa pm4.13 imbi2i df-an bicon2i bitr ) ABCABDZDZCZAKEZDBLABFGNMAKHIJ
    $.
    $( [5-Aug-93] $)

  $( Express conjunction in terms of implication. $)
  annim $p |- ( ( ph /\ -. ps ) <-> -. ( ph -> ps ) ) $=
    ( wi wn wa iman bicon2i ) ABCABDEABFG $.
    $( [2-Aug-94] $)

  $( Theorem *4.61 of [WhiteheadRussell] p. 120. $)
  pm4.61 $p |-  ( -. ( ph -> ps ) <-> ( ph /\ -. ps ) ) $=
    ( wn wa wi annim bicomi ) ABCDABECABFG $.
    $( [24-Feb-05] $) $( [3-Jan-05] $)

  $( Theorem *4.65 of [WhiteheadRussell] p. 120. $)
  pm4.65 $p |-  ( -. ( -. ph -> ps ) <-> ( -. ph /\ -. ps ) ) $=
    ( wn pm4.61 ) ACBD $.
    $( [24-Feb-05] $) $( [3-Jan-05] $)

  $( Theorem *4.67 of [WhiteheadRussell] p. 120. $)
  pm4.67 $p |-  ( -. ( -. ph -> -. ps ) <-> ( -. ph /\ ps ) ) $=
    ( wn pm4.63 ) ACBD $.
    $( [27-Feb-05] $) $( [3-Jan-05] $)

  $( Express implication in terms of conjunction. $)
  imnan $p |- ( ( ph -> -. ps ) <-> -. ( ph /\ ps ) ) $=
    ( wa wn wi df-an bicon2i ) ABCABDEABFG $.
    $( [9-Apr-94] $)

  $( Idempotent law for disjunction.  Theorem *4.25 of [WhiteheadRussell]
     p. 117. $)
  oridm $p |- ( ( ph \/ ph ) <-> ph ) $=
    ( wo wn wi df-or pm2.24 pm2.18 impbi bitr4 ) AABACADZAAAEAJAAFAGHI $.
    $( [5-Aug-93] $)

  $( Theorem *4.25 of [WhiteheadRussell] p. 117. $)
  pm4.25 $p |-  ( ph <-> ( ph \/ ph ) ) $=
    ( wo oridm bicomi ) AABAACD $.
    $( [27-Feb-05] $) $( [3-Jan-05] $)

  $( Axiom *1.2 (Taut) of [WhiteheadRussell] p. 96. $)
  pm1.2 $p |-  ( ( ph \/ ph ) -> ph ) $=
    ( wo oridm biimp ) AABAACD $.
    $( [27-Feb-05] $) $( [3-Jan-05] $)

  $( Commutative law for disjunction.  Theorem *4.31 of [WhiteheadRussell]
     p. 118. $)
  orcom $p |- ( ( ph \/ ps ) <-> ( ps \/ ph ) ) $=
    ( wn wi wo bi2.15 df-or 3bitr4 ) ACBDBCADABEBAEABFABGBAGH $.
    $( [5-Aug-93] $)

  $( Axiom *1.4 of [WhiteheadRussell] p. 96. $)
  pm1.4 $p |-  ( ( ph \/ ps ) -> ( ps \/ ph ) ) $=
    ( wo orcom biimp ) ABCBACABDE $.
    $( [27-Feb-05] $) $( [3-Jan-05] $)

  $( Theorem *2.62 of [WhiteheadRussell] p. 107. $)
  pm2.62 $p |-  ( ( ph \/ ps ) -> ( ( ph -> ps ) -> ps ) ) $=
    ( wo wi dfor2 biimp ) ABCABDBDABEF $.
    $( [6-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.621 of [WhiteheadRussell] p. 107. $)
  pm2.621 $p |-  ( ( ph -> ps ) -> ( ( ph \/ ps ) -> ps ) ) $=
    ( wo wi pm2.62 com12 ) ABCABDBABEF $.
    $( [6-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.68 of [WhiteheadRussell] p. 108. $)
  pm2.68 $p |-  ( ( ( ph -> ps ) -> ps ) -> ( ph \/ ps ) ) $=
    ( wo wi dfor2 biimpr ) ABCABDBDABEF $.
    $( [27-Feb-05] $) $( [3-Jan-05] $)

  $( Elimination of disjunction by denial of a disjunct.  Theorem *2.55 of
     [WhiteheadRussell] p. 107. $)
  orel1 $p |- ( -. ph -> ( ( ph \/ ps ) -> ps ) ) $=
    ( wo wn wi df-or biimp com12 ) ABCZADZBIJBEABFGH $.
    $( [12-Aug-94] $)

  $( Elimination of disjunction by denial of a disjunct.  Theorem *2.56 of
     [WhiteheadRussell] p. 107. $)
  orel2 $p |- ( -. ph -> ( ( ps \/ ph ) -> ps ) ) $=
    ( wn wo orel1 orcom syl5ib ) ACABDBBADABEBAFG $.
    $( [12-Aug-94] $)

  $( Theorem *2.25 of [WhiteheadRussell] p. 104. $)
  pm2.25 $p |-  ( ph \/ ( ( ph \/ ps ) -> ps ) ) $=
    ( wo wi orel1 orri ) AABCBDABEF $.
    $( [1-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *2.53 of [WhiteheadRussell] p. 107. $)
  pm2.53 $p |-  ( ( ph \/ ps ) -> ( -. ph -> ps ) ) $=
    ( wn wo orel1 com12 ) ACABDBABEF $.
    $( [1-Mar-05] $) $( [3-Jan-05] $)

  ${
    bi.oa $e |- ( ph <-> ps ) $.

    $( Inference adding a left disjunct to both sides of a logical
       equivalence. $)
    orbi2i $p |- ( ( ch \/ ph ) <-> ( ch \/ ps ) ) $=
      ( wn wi wo imbi2i df-or 3bitr4 ) CEZAFKBFCAGCBGABKDHCAICBIJ $.
      $( [5-Aug-93] $)

    $( Inference adding a right disjunct to both sides of a logical
       equivalence. $)
    orbi1i $p |- ( ( ph \/ ch ) <-> ( ps \/ ch ) ) $=
      ( wo orcom orbi2i 3bitr ) ACECAECBEBCEACFABCDGCBFH $.
      $( [5-Aug-93] $)

  $}

  ${
    bi2or.1 $e |- ( ph <-> ps ) $.
    bi2or.2 $e |- ( ch <-> th ) $.
    $( Infer the disjunction of two equivalences. $)
    orbi12i $p |- ( ( ph \/ ch ) <-> ( ps \/ th ) ) $=
      ( wo orbi2i orbi1i bitr ) ACGADGBDGCDAFHABDEIJ $.
      $( [5-Aug-93] $)
  $}

  $( A rearrangement of disjuncts. $)
  or12 $p |- ( ( ph \/ ( ps \/ ch ) ) <-> ( ps \/ ( ph \/ ch ) ) ) $=
    ( wn wo wi bi2.04 df-or imbi2i 3bitr4r 3bitr4 ) ADZBCEZFZBDZACEZFZAMEBPEOLC
    FZFLOCFZFQNOLCGPROACHIMSLBCHIJAMHBPHK $.
    $( [5-Aug-93] $)

  $( Axiom *1.5 (Assoc) of [WhiteheadRussell] p. 96. $)
  pm1.5 $p |-  ( ( ph \/ ( ps \/ ch ) ) -> ( ps \/ ( ph \/ ch ) ) ) $=
    ( wo or12 biimp ) ABCDDBACDDABCEF $.
    $( [1-Mar-05] $) $( [3-Jan-05] $)

  $( Associative law for disjunction.  Theorem *4.33 of [WhiteheadRussell]
     p. 118. $)
  orass $p |- ( ( ( ph \/ ps ) \/ ch ) <-> ( ph \/ ( ps \/ ch ) ) ) $=
    ( wo or12 orcom orbi2i 3bitr4 ) CABDZDACBDZDICDABCDZDCABEICFKJABCFGH $.
    $( [5-Aug-93] $)

  $( Theorem *2.31 of [WhiteheadRussell] p. 104. $)
  pm2.31 $p |-  ( ( ph \/ ( ps \/ ch ) ) -> ( ( ph \/ ps ) \/ ch ) ) $=
    ( wo orass biimpr ) ABDCDABCDDABCEF $.
    $( [2-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *2.32 of [WhiteheadRussell] p. 105. $)
  pm2.32 $p |-  ( ( ( ph \/ ps ) \/ ch ) -> ( ph \/ ( ps \/ ch ) ) ) $=
    ( wo orass biimp ) ABDCDABCDDABCEF $.
    $( [6-Mar-05] $) $( [3-Jan-05] $)

  $( A rearrangement of disjuncts. $)
  or23 $p |- ( ( ( ph \/ ps ) \/ ch ) <-> ( ( ph \/ ch ) \/ ps ) ) $=
    ( wo orcom orbi2i orass 3bitr4 ) ABCDZDACBDZDABDCDACDBDIJABCEFABCGACBGH $.
    $( [18-Oct-95] $)

  $( Rearrangement of 4 disjuncts. $)
  or4 $p |- ( ( ( ph \/ ps ) \/ ( ch \/ th ) ) <->
                ( ( ph \/ ch ) \/ ( ps \/ th ) ) ) $=
    ( wo or12 orbi2i orass 3bitr4 ) ABCDEZEZEACBDEZEZEABEJEACELEKMABCDFGABJHACL
    HI $.
    $( [12-Aug-94] $)

  $( Rearrangement of 4 disjuncts. $)
  or42 $p |- ( ( ( ph \/ ps ) \/ ( ch \/ th ) ) <->
                 ( ( ph \/ ch ) \/ ( th \/ ps ) ) ) $=
    ( wo or4 orcom orbi2i bitr ) ABECDEEACEZBDEZEJDBEZEABCDFKLJBDGHI $.
    $( [11-Jan-05] $) $( [10-Jan-05] $)

  $( Distribution of disjunction over disjunction. $)
  orordi $p |- ( ( ph \/ ( ps \/ ch ) ) <->
               ( ( ph \/ ps ) \/ ( ph \/ ch ) ) ) $=
    ( wo oridm orbi1i or4 bitr3 ) ABCDZDAADZIDABDACDDJAIAEFAABCGH $.
    $( [25-Feb-95] $)

  $( Distribution of disjunction over disjunction. $)
  orordir $p |- ( ( ( ph \/ ps ) \/ ch ) <->
               ( ( ph \/ ch ) \/ ( ps \/ ch ) ) ) $=
    ( wo oridm orbi2i or4 bitr3 ) ABDZCDICCDZDACDBCDDJCICEFABCCGH $.
    $( [25-Feb-95] $)

  $( Introduction of a disjunct.  Axiom *1.3 of [WhiteheadRussell] p. 96. $)
  olc $p |- ( ph -> ( ps \/ ph ) ) $=
    ( wn ax-1 orrd ) ABAABCDE $.
    $( [30-Aug-93] $)

  $( Theorem *2.07 of [WhiteheadRussell] p. 101. $)
  pm2.07 $p |-  ( ph -> ( ph \/ ph ) ) $=
    ( olc ) AAB $.
    $( [6-Mar-05] $) $( [3-Jan-05] $)

  $( Introduction of a disjunct.  Theorem *2.2 of [WhiteheadRussell] p. 104. $)
  orc $p |- ( ph -> ( ph \/ ps ) ) $=
    ( pm2.24 orrd ) AABABCD $.
    $( [30-Aug-93] $)

  ${
    orci.1 $e |- ( ( ph \/ ps ) -> ch ) $.
    $( Deduction eliminating disjunct. $)
    orci $p |- ( ph -> ch ) $=
      ( wo orc syl ) AABECABFDG $.
      $( [21-Jun-94] $)
  $}

  ${
    olci.1 $e |- ( ( ph \/ ps ) -> ch ) $.
    $( Deduction eliminating disjunct. $)
    olci $p |- ( ps -> ch ) $=
      ( wo olc syl ) BABECBAFDG $.
      $( [21-Jun-94] $)
  $}

  $( Theorem *2.45 of [WhiteheadRussell] p. 106. $)
  pm2.45 $p |-  ( -. ( ph \/ ps ) -> -. ph ) $=
    ( wo orc con3i ) AABCABDE $.
    $( [8-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.46 of [WhiteheadRussell] p. 106. $)
  pm2.46 $p |-  ( -. ( ph \/ ps ) -> -. ps ) $=
    ( wo olc con3i ) BABCBADE $.
    $( [8-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.47 of [WhiteheadRussell] p. 107. $)
  pm2.47 $p |-  ( -. ( ph \/ ps ) -> ( -. ph \/ ps ) ) $=
    ( wo wn pm2.45 orc syl ) ABCDADZHBCABEHBFG $.
    $( [6-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *2.48 of [WhiteheadRussell] p. 107. $)
  pm2.48 $p |-  ( -. ( ph \/ ps ) -> ( ph \/ -. ps ) ) $=
    ( wo wn pm2.46 a1d orrd ) ABCDZABDZHIADABEFG $.
    $( [9-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *2.49 of [WhiteheadRussell] p. 107. $)
  pm2.49 $p |-  ( -. ( ph \/ ps ) -> ( -. ph \/ -. ps ) ) $=
    ( wo wn pm2.46 a1d orrd ) ABCDZADZBDZHJIDABEFG $.
    $( [7-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *2.67 of [WhiteheadRussell] p. 107. $)
  pm2.67 $p |-  ( ( ( ph \/ ps ) -> ps ) -> ( ph -> ps ) ) $=
    ( wo orc syl4 ) AABCBABDE $.
    $( [6-Jan-05] $) $( [3-Jan-05] $)

  $( Join antecedents with conjunction.  Theorem *3.2 of [WhiteheadRussell]
     p. 111. $)
  pm3.2 $p |- ( ph -> ( ps -> ( ph /\ ps ) ) ) $=
    ( wa wn wi df-an biimpr expi ) ABABCZIABDEDABFGH $.
    $( [5-Aug-93] $)

  $( Join antecedents with conjunction.  Theorem *3.21 of
     [WhiteheadRussell] p. 111. $)
  pm3.21 $p |- ( ph -> ( ps -> ( ps /\ ph ) ) ) $=
    ( wa pm3.2 com12 ) BABACBADE $.
    $( [5-Aug-93] $)

  ${
    pm3.2i.1 $e |- ph $.
    pm3.2i.2 $e |- ps $.
    $( Infer conjunction of premises. $)
    pm3.2i $p |- ( ph /\ ps ) $=
      ( wa pm3.2 mp2 ) ABABECDABFG $.
      $( [5-Aug-93] $)
  $}

  $( Theorem *3.37 (Transp) of [WhiteheadRussell] p. 112. $)
  pm3.37 $p |-  ( ( ( ph /\ ps ) -> ch ) -> ( ( ph /\ -. ch ) -> -. ps ) ) $=
    ( wa wi wn pm3.21 syl4d com12 iman syl6ib con2d ) ABDZCEZBACFDZNBACEZOFBNPB
    AMCBAGHIACJKL $.
    $( [7-Mar-05] $) $( [3-Jan-05] $)

  $( Nested conjunction of antecedents. $)
  pm3.43i $p |- ( ( ph -> ps ) ->
                ( ( ph -> ch ) -> ( ph -> ( ps /\ ch ) ) ) ) $=
    ( wi wa pm3.2 syl3 a2d ) ABDACBCEZBCIDABCFGH $.
    $( [5-Aug-93] $)

  ${
    jca.1 $e |- ( ph -> ps ) $.
    jca.2 $e |- ( ph -> ch ) $.
    $( Deduce conjunction of the consequents of two implications ("join
       consequents with 'and'"). $)
    jca $p |- ( ph -> ( ps /\ ch ) ) $=
      ( wn wi wa jc df-an sylibr ) ABCFGFBCHABCDEIBCJK $.
      $( [5-Aug-93] $)
  $}

  ${
    jcai.1 $e |- ( ph -> ps ) $.
    jcai.2 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction replacing implication with conjunction. $)
    jcai $p |- ( ph -> ( ps /\ ch ) ) $=
      ( mpd jca ) ABCDABCDEFG $.
      $( [5-Aug-93] $)
  $}

  ${
    jctl.1 $e |- ps $.
    $( Inference conjoining a theorem to the left of a consequent. $)
    jctl $p |- ( ph -> ( ps /\ ph ) ) $=
      ( a1i id jca ) ABABACDAEF $.
      $( [31-Dec-93] $)
  $}

  ${
    jctr.1 $e |- ps $.
    $( Inference conjoining a theorem to the right of a consequent. $)
    jctr $p |- ( ph -> ( ph /\ ps ) ) $=
      ( id a1i jca ) AABADBACEF $.
      $( [18-Aug-93] $)
  $}

  ${
    jctil.1 $e |- ( ph -> ps ) $.
    jctil.2 $e |- ch $.
    $( Inference conjoining a theorem to left of consequent in an
       implication. $)
    jctil $p |- ( ph -> ( ch /\ ps ) ) $=
      ( a1i jca ) ACBCAEFDG $.
      $( [31-Dec-93] $)
  $}

  ${
    jctir.1 $e |- ( ph -> ps ) $.
    jctir.2 $e |- ch $.
    $( Inference conjoining a theorem to right of consequent in an
       implication. $)
    jctir $p |- ( ph -> ( ps /\ ch ) ) $=
      ( a1i jca ) ABCDCAEFG $.
      $( [31-Dec-93] $)
  $}

  $( Conjoin antecedent to left of consequent. $)
  ancl $p |- ( ( ph -> ps ) -> ( ph -> ( ph /\ ps ) ) ) $=
    ( wa pm3.2 a2i ) ABABCABDE $.
    $( [15-Aug-94] $)

  $( Conjoin antecedent to right of consequent. $)
  ancr $p |- ( ( ph -> ps ) -> ( ph -> ( ps /\ ph ) ) ) $=
    ( wa pm3.21 a2i ) ABBACABDE $.
    $( [15-Aug-94] $)

  ${
    ancli.1 $e |- ( ph -> ps ) $.
    $( Deduction conjoining antecedent to left of consequent. $)
    ancli $p |- ( ph -> ( ph /\ ps ) ) $=
      ( id jca ) AABADCE $.
      $( [12-Aug-93] $)
  $}

  ${
    ancri.1 $e |- ( ph -> ps ) $.
    $( Deduction conjoining antecedent to right of consequent. $)
    ancri $p |- ( ph -> ( ps /\ ph ) ) $=
      ( id jca ) ABACADE $.
      $( [15-Aug-94] $)
  $}

  ${
    ancld.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction conjoining antecedent to left of consequent in nested
       implication. $)
    ancld $p |- ( ph -> ( ps -> ( ps /\ ch ) ) ) $=
      ( wi wa ancl syl ) ABCEBBCFEDBCGH $.
      $( [15-Aug-94] $)
  $}

  ${
    ancrd.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction conjoining antecedent to right of consequent in nested
       implication. $)
    ancrd $p |- ( ph -> ( ps -> ( ch /\ ps ) ) ) $=
      ( wi wa ancr syl ) ABCEBCBFEDBCGH $.
      $( [15-Aug-94] $)
  $}

  $( Conjoin antecedent to left of consequent in nested implication. $)
  anc2l $p |- ( ( ph -> ( ps -> ch ) ) -> ( ph -> ( ps -> ( ph /\ ch ) ) ) ) $=
    ( wi wa pm3.2 syl3d a2i ) ABCDBACEZDACIBACFGH $.
    $( [10-Aug-94] $)

  $( Conjoin antecedent to right of consequent in nested implication. $)
  anc2r $p |- ( ( ph -> ( ps -> ch ) ) -> ( ph -> ( ps -> ( ch /\ ph ) ) ) ) $=
    ( wi wa pm3.21 syl3d a2i ) ABCDBCAEZDACIBACFGH $.
    $( [15-Aug-94] $)

  ${
    anc2li.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction conjoining antecedent to left of consequent in nested
       implication. $)
    anc2li $p |- ( ph -> ( ps -> ( ph /\ ch ) ) ) $=
      ( wi wa anc2l ax-mp ) ABCEEABACFEEDABCGH $.
      $( [10-Aug-94] $)
  $}

  ${
    anc2ri.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction conjoining antecedent to right of consequent in nested
       implication. $)
    anc2ri $p |- ( ph -> ( ps -> ( ch /\ ph ) ) ) $=
      ( wi wa anc2r ax-mp ) ABCEEABCAFEEDABCGH $.
      $( [15-Aug-94] $)
  $}

  $( Conjunction in terms of disjunction (DeMorgan's law).  Theorem *4.5 of
     [WhiteheadRussell] p. 120. $)
  anor $p |- ( ( ph /\ ps ) <-> -. ( -. ph \/ -. ps ) ) $=
    ( wa wn wi wo df-an imor negbii bitr ) ABCABDZEZDADKFZDABGLMAKHIJ $.
    $( [5-Aug-93] $)

  $( Negated conjunction in terms of disjunction (DeMorgan's law).  Theorem
     *4.51 of [WhiteheadRussell] p. 120. $)
  ianor $p |- ( -. ( ph /\ ps ) <-> ( -. ph \/ -. ps ) ) $=
    ( wa wn wo anor negbii pm4.13 bitr4 ) ABCZDADBDEZDZDKJLABFGKHI $.
    $( [5-Aug-93] $)

  $( Negated disjunction in terms of conjunction (DeMorgan's law).  Compare
     Theorem *4.56 of [WhiteheadRussell] p. 120. $)
  ioran $p |- ( -. ( ph \/ ps ) <-> ( -. ph /\ -. ps ) ) $=
    ( wo wn wa pm4.13 orbi12i negbii anor bitr4 ) ABCZDADZDZBDZDZCZDLNEKPAMBOAF
    BFGHLNIJ $.
    $( [5-Aug-93] $)

  $( Theorem *4.52 of [WhiteheadRussell] p. 120. $)
  pm4.52 $p |-  ( ( ph /\ -. ps ) <-> -. ( -. ph \/ ps ) ) $=
    ( wn wa wo anor pm4.13 orbi2i negbii bitr4 ) ABCZDACZKCZEZCLBEZCAKFONBMLBGH
    IJ $.
    $( [11-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *4.53 of [WhiteheadRussell] p. 120. $)
  pm4.53 $p |-  ( -. ( ph /\ -. ps ) <-> ( -. ph \/ ps ) ) $=
    ( wn wo wa pm4.52 bicon2i bicomi ) ACBDZABCEZCJIABFGH $.
    $( [11-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *4.54 of [WhiteheadRussell] p. 120. $)
  pm4.54 $p |-  ( ( -. ph /\ ps ) <-> -. ( ph \/ -. ps ) ) $=
    ( wn wa wo anor pm4.13 orbi1i negbii bitr4 ) ACZBDKCZBCZEZCAMEZCKBFONALMAGH
    IJ $.
    $( [11-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *4.55 of [WhiteheadRussell] p. 120. $)
  pm4.55 $p |-  ( -. ( -. ph /\ ps ) <-> ( ph \/ -. ps ) ) $=
    ( wn wo wa pm4.54 bicon2i bicomi ) ABCDZACBEZCJIABFGH $.
    $( [11-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *4.56 of [WhiteheadRussell] p. 120. $)
  pm4.56 $p |-  ( ( -. ph /\ -. ps ) <-> -. ( ph \/ ps ) ) $=
    ( wo wn wa ioran bicomi ) ABCDADBDEABFG $.
    $( [11-Mar-05] $) $( [3-Jan-05] $)

  $( Disjunction in terms of conjunction (DeMorgan's law).  Compare Theorem
     *4.57 of [WhiteheadRussell] p. 120. $)
  oran $p |- ( ( ph \/ ps ) <-> -. ( -. ph /\ -. ps ) ) $=
    ( wo wn wa pm4.13 ioran negbii bitr ) ABCZJDZDADBDEZDJFKLABGHI $.
    $( [5-Aug-93] $)

  $( Theorem *4.57 of [WhiteheadRussell] p. 120. $)
  pm4.57 $p |-  ( -. ( -. ph /\ -. ps ) <-> ( ph \/ ps ) ) $=
    ( wo wn wa oran bicomi ) ABCADBDEDABFG $.
    $( [11-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *3.1 of [WhiteheadRussell] p. 111. $)
  pm3.1 $p |-  ( ( ph /\ ps ) -> -. ( -. ph \/ -. ps ) ) $=
    ( wa wn wo anor biimp ) ABCADBDEDABFG $.
    $( [21-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *3.11 of [WhiteheadRussell] p. 111. $)
  pm3.11 $p |-  ( -. ( -. ph \/ -. ps ) -> ( ph /\ ps ) ) $=
    ( wa wn wo anor biimpr ) ABCADBDEDABFG $.
    $( [25-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *3.12 of [WhiteheadRussell] p. 111. $)
  pm3.12 $p |-  ( ( -. ph \/ -. ps ) \/ ( ph /\ ps ) ) $=
    ( wn wo wa pm3.11 orri ) ACBCDABEABFG $.
    $( [25-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *3.13 of [WhiteheadRussell] p. 111. $)
  pm3.13 $p |-  ( -. ( ph /\ ps ) -> ( -. ph \/ -. ps ) ) $=
    ( wn wo wa pm3.11 con1i ) ACBCDABEABFG $.
    $( [25-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *3.14 of [WhiteheadRussell] p. 111. $)
  pm3.14 $p |-  ( ( -. ph \/ -. ps ) -> -. ( ph /\ ps ) ) $=
    ( wa wn wo pm3.1 con2i ) ABCADBDEABFG $.
    $( [25-Mar-05] $) $( [3-Jan-05] $)

  $( Elimination of a conjunct.  Theorem *3.26 (Simp) of [WhiteheadRussell]
     p. 112. $)
  pm3.26 $p |- ( ( ph /\ ps ) -> ph ) $=
    ( wa wn wi df-an pm3.26im sylbi ) ABCABDEDAABFABGH $.
    $( [5-Aug-93] $)

  ${
    pm3.26i.1 $e |- ( ph /\ ps ) $.
    $( Inference eliminating a conjunct. $)
    pm3.26i $p |- ph $=
      ( wa pm3.26 ax-mp ) ABDACABEF $.
      $( [15-Jun-94] $)
  $}

  ${
    pm3.26d.1 $e |- ( ph -> ( ps /\ ch ) ) $.
    $( Deduction eliminating a conjunct. $)
    pm3.26d $p |- ( ph -> ps ) $=
      ( wa pm3.26 syl ) ABCEBDBCFG $.
      $( [5-Aug-93] $)
  $}

  ${
    pm3.26bd.1 $e |- ( ph <-> ( ps /\ ch ) ) $.
    $( Deduction eliminating a conjunct. $)
    pm3.26bd $p |- ( ph -> ps ) $=
      ( wa biimp pm3.26d ) ABCABCEDFG $.
      $( [27-May-98] $)
  $}

  $( Elimination of a conjunct.  Theorem *3.27 (Simp) of [WhiteheadRussell]
     p. 112. $)
  pm3.27 $p |- ( ( ph /\ ps ) -> ps ) $=
    ( wa wn wi df-an pm3.27im sylbi ) ABCABDEDBABFABGH $.
    $( [5-Aug-93] $)

  ${
    pm3.27i.1 $e |- ( ph /\ ps ) $.
    $( Inference eliminating a conjunct. $)
    pm3.27i $p |- ps $=
      ( wa pm3.27 ax-mp ) ABDBCABEF $.
      $( [15-Jun-94] $)
  $}

  ${
    pm3.27d.1 $e |- ( ph -> ( ps /\ ch ) ) $.
    $( Deduction eliminating a conjunct. $)
    pm3.27d $p |- ( ph -> ch ) $=
      ( wa pm3.27 syl ) ABCECDBCFG $.
      $( [5-Aug-93] $)
  $}

  ${
    pm3.27bd.1 $e |- ( ph <-> ( ps /\ ch ) ) $.
    $( Deduction eliminating a conjunct. $)
    pm3.27bd $p |- ( ph -> ch ) $=
      ( wa biimp pm3.27d ) ABCABCEDFG $.
      $( [27-May-98] $)
  $}

  $( Theorem *3.41 of [WhiteheadRussell] p. 113. $)
  pm3.41 $p |-  ( ( ph -> ch ) -> ( ( ph /\ ps ) -> ch ) ) $=
    ( wa pm3.26 syl4 ) ABDACABEF $.
    $( [21-Mar-05] $)


  $( Conjoin antecedent to left of consequent.  Theorem *4.7 of
     [WhiteheadRussell] p. 120. $)
  anclb $p |- ( ( ph -> ps ) <-> ( ph -> ( ph /\ ps ) ) ) $=
    ( wi wa ancl pm3.27 syl3 impbi ) ABCAABDZCABEIBAABFGH $.
    $( [25-Jul-99] $)

  $( Conjoin antecedent to right of consequent. $)
  ancrb $p |- ( ( ph -> ps ) <-> ( ph -> ( ps /\ ph ) ) ) $=
    ( wi wa ancr pm3.26 syl3 impbi ) ABCABADZCABEIBABAFGH $.
    $( [25-Jul-99] $)

  $( Conjunction implies implication.  Theorem *3.4 of [WhiteheadRussell]
     p. 113. $)
  pm3.4 $p |- ( ( ph /\ ps ) -> ( ph -> ps ) ) $=
    ( wa pm3.27 a1d ) ABCBAABDE $.
    $( [31-Jul-95] $)

  $( Conjunction with implication.  Compare Theorem *4.45 of
     [WhiteheadRussell] p. 119. $)
  pm4.45im $p |- ( ph <-> ( ph /\ ( ps -> ph ) ) ) $=
    ( wi wa ax-1 ancli pm3.26 impbi ) AABACZDAIABEFAIGH $.
    $( [17-May-98] $)

  ${
    anim12i.1 $e |- ( ph -> ps ) $.
    anim12i.2 $e |- ( ch -> th ) $.
    $( Conjoin antecedents and consequents of two premises. $)
    anim12i $p |- ( ( ph /\ ch ) -> ( ps /\ th ) ) $=
      ( wa pm3.26 syl pm3.27 jca ) ACGZBDLABACHEILCDACJFIK $.
      $( [5-Aug-93] $)
  $}

  ${
    anim1i.1 $e |- ( ph -> ps ) $.
    $( Introduce conjunct to both sides of an implication. $)
    anim1i $p |- ( ( ph /\ ch ) -> ( ps /\ ch ) ) $=
      ( id anim12i ) ABCCDCEF $.
      $( [5-Aug-93] $)

    $( Introduce conjunct to both sides of an implication. $)
    anim2i $p |- ( ( ch /\ ph ) -> ( ch /\ ps ) ) $=
      ( id anim12i ) CCABCEDF $.
      $( [5-Aug-93] $)
  $}

  ${
    orim12i.1 $e |- ( ph -> ps ) $.
    orim12i.2 $e |- ( ch -> th ) $.
    $( Conjoin antecedents and consequents of two premises. $)
    orim12i $p |- ( ( ph \/ ch ) -> ( ps \/ th ) ) $=
      ( wn wa wo con3i anim12i oran 3imtr4 ) AGZCGZHZGBGZDGZHZGACIBDISPQNROABEJ
      CDFJKJACLBDLM $.
      $( [6-Jun-94] $)
  $}

  ${
    orim1i.1 $e |- ( ph -> ps ) $.
    $( Introduce disjunct to both sides of an implication. $)
    orim1i $p |- ( ( ph \/ ch ) -> ( ps \/ ch ) ) $=
      ( id orim12i ) ABCCDCEF $.
      $( [6-Jun-94] $)

    $( Introduce disjunct to both sides of an implication. $)
    orim2i $p |- ( ( ch \/ ph ) -> ( ch \/ ps ) ) $=
      ( id orim12i ) CCABCEDF $.
      $( [6-Jun-94] $)
  $}

  $( Disjunction of antecedents.  Compare Theorem *3.44 of
     [WhiteheadRussell] p. 113. $)
  jao $p |- ( ( ph -> ps ) -> ( ( ch -> ps ) -> ( ( ph \/ ch ) -> ps ) ) ) $=
    ( wi wn wo con3 wa pm3.43i con1 syl6 oran bisyl7 syl5 syl ) ABDBEZAEZDZCBDZ
    ACFZBDZDABGRPCEZDZUASRUCQUBHZEZBTRUCPUDDUEBDPQUBIBUDJKACLMCBGNO $.
    $( [5-Apr-94] $)

  ${
    jaoi.1 $e |- ( ph -> ps ) $.
    jaoi.2 $e |- ( ch -> ps ) $.
    $( Inference disjoining the antecedents of two implications. $)
    jaoi $p |- ( ( ph \/ ch ) -> ps ) $=
      ( wi wo jao mp2 ) ABFCBFACGBFDEABCHI $.
      $( [5-Apr-94] $)
  $}

  $( Import-export theorem.  Part of Theorem *4.87 of [WhiteheadRussell]
     p. 122. $)
  impexp $p |- ( ( ( ph /\ ps ) -> ch ) <-> ( ph -> ( ps -> ch ) ) ) $=
    ( wa wi wn df-an imbi1i expt impt impbi bitr ) ABDZCEABFEFZCEZABCEEZMNCABGH
    OPABCIABCJKL $.
    $( [5-Aug-93] $)


  ${
    imp.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Importation inference. $)
    imp $p |- ( ( ph /\ ps ) -> ch ) $=
      ( wa wn wi df-an impi sylbi ) ABEABFGFCABHABCDIJ $.
      $( [5-Aug-93] $)
  $}

  $( Conjunctive detachment.  Theorem *3.35 of [WhiteheadRussell] p. 112. $)
  pm3.35 $p |- ( ( ph /\ ( ph -> ps ) ) -> ps ) $=
    ( wi pm2.27 imp ) AABCBABDE $.
    $( [14-Dec-02] $)


  ${
    imp3.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.

    $( Importation deduction. $)
    imp3a $p |- ( ph -> ( ( ps /\ ch ) -> th ) ) $=
      ( wi wa impexp sylibr ) ABCDFFBCGDFEBCDHI $.
      $( [31-Mar-94] $)

    $( An importation inference. $)
    imp31 $p |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $=
      ( wa wi imp ) ABFCDABCDGEHH $.
      $( [26-Apr-94] $)

    $( An importation inference. $)
    imp32 $p |- ( ( ph /\ ( ps /\ ch ) ) -> th ) $=
      ( wa imp3a imp ) ABCFDABCDEGH $.
      $( [26-Apr-94] $)

  $}

  ${
    imp4.1 $e |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $.

    $( An importation inference. $)
    imp4a $p |- ( ph -> ( ps -> ( ( ch /\ th ) -> ta ) ) ) $=
      ( wi wa impexp syl6ibr ) ABCDEGGCDHEGFCDEIJ $.
      $( [26-Apr-94] $)

    $( An importation inference. $)
    imp4b $p |- ( ( ph /\ ps ) -> ( ( ch /\ th ) -> ta ) ) $=
      ( wa wi imp4a imp ) ABCDGEHABCDEFIJ $.
      $( [26-Apr-94] $)

    $( An importation inference. $)
    imp4c $p |- ( ph -> ( ( ( ps /\ ch ) /\ th ) -> ta ) ) $=
      ( wa wi imp3a ) ABCGDEABCDEHFII $.
      $( [26-Apr-94] $)

    $( An importation inference. $)
    imp4d $p |- ( ph -> ( ( ps /\ ( ch /\ th ) ) -> ta ) ) $=
      ( wa imp4a imp3a ) ABCDGEABCDEFHI $.
      $( [26-Apr-94] $)

    $( An importation inference. $)
    imp41 $p |- ( ( ( ( ph /\ ps ) /\ ch ) /\ th ) -> ta ) $=
      ( wa wi imp imp31 ) ABGCDEABCDEHHFIJ $.
      $( [26-Apr-94] $)

    $( An importation inference. $)
    imp42 $p |- ( ( ( ph /\ ( ps /\ ch ) ) /\ th ) -> ta ) $=
      ( wa wi imp32 imp ) ABCGGDEABCDEHFIJ $.
      $( [26-Apr-94] $)

    $( An importation inference. $)
    imp43 $p |- ( ( ( ph /\ ps ) /\ ( ch /\ th ) ) -> ta ) $=
      ( wa imp4b imp ) ABGCDGEABCDEFHI $.
      $( [26-Apr-94] $)

    $( An importation inference. $)
    imp44 $p |- ( ( ph /\ ( ( ps /\ ch ) /\ th ) ) -> ta ) $=
      ( wa imp4c imp ) ABCGDGEABCDEFHI $.
      $( [26-Apr-94] $)

    $( An importation inference. $)
    imp45 $p |- ( ( ph /\ ( ps /\ ( ch /\ th ) ) ) -> ta ) $=
      ( wa imp4d imp ) ABCDGGEABCDEFHI $.
      $( [26-Apr-94] $)

  $}

  ${
    exp.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    $( Exportation inference. $)
    exp $p |- ( ph -> ( ps -> ch ) ) $=
      ( wn wi wa df-an sylbir expi ) ABCABEFEABGCABHDIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    exp3a.1 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    $( Exportation deduction. $)
    exp3a $p |- ( ph -> ( ps -> ( ch -> th ) ) ) $=
      ( wa wi impexp sylib ) ABCFDGBCDGGEBCDHI $.
      $( [20-Aug-93] $)
  $}

  ${
    exp31.1 $e |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $.
    $( An exportation inference. $)
    exp31 $p |- ( ph -> ( ps -> ( ch -> th ) ) ) $=
      ( wi wa exp ) ABCDFABGCDEHH $.
      $( [26-Apr-94] $)
  $}

  ${
    exp32.1 $e |- ( ( ph /\ ( ps /\ ch ) ) -> th ) $.
    $( An exportation inference. $)
    exp32 $p |- ( ph -> ( ps -> ( ch -> th ) ) ) $=
      ( wa exp exp3a ) ABCDABCFDEGH $.
      $( [26-Apr-94] $)
  $}

  ${
    exp4a.1 $e |- ( ph -> ( ps -> ( ( ch /\ th ) -> ta ) ) ) $.
    $( An exportation inference. $)
    exp4a $p |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $=
      ( wa wi impexp syl6ib ) ABCDGEHCDEHHFCDEIJ $.
      $( [26-Apr-94] $)
  $}

  ${
    exp4b.1 $e |- ( ( ph /\ ps ) -> ( ( ch /\ th ) -> ta ) ) $.
    $( An exportation inference. $)
    exp4b $p |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $=
      ( wi wa exp3a exp ) ABCDEGGABHCDEFIJ $.
      $( [26-Apr-94] $)
  $}

  ${
    exp4c.1 $e |- ( ph -> ( ( ( ps /\ ch ) /\ th ) -> ta ) ) $.
    $( An exportation inference. $)
    exp4c $p |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $=
      ( wi wa exp3a ) ABCDEGABCHDEFII $.
      $( [26-Apr-94] $)
  $}

  ${
    exp4d.1 $e |- ( ph -> ( ( ps /\ ( ch /\ th ) ) -> ta ) ) $.
    $( An exportation inference. $)
    exp4d $p |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $=
      ( wa exp3a exp4a ) ABCDEABCDGEFHI $.
      $( [26-Apr-94] $)
  $}

  ${
    exp41.1 $e |- ( ( ( ( ph /\ ps ) /\ ch ) /\ th ) -> ta ) $.
    $( An exportation inference. $)
    exp41 $p |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $=
      ( wi wa exp exp31 ) ABCDEGABHCHDEFIJ $.
      $( [26-Apr-94] $)
  $}

  ${
    exp42.1 $e |- ( ( ( ph /\ ( ps /\ ch ) ) /\ th ) -> ta ) $.
    $( An exportation inference. $)
    exp42 $p |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $=
      ( wi wa exp31 exp3a ) ABCDEGABCHDEFIJ $.
      $( [26-Apr-94] $)
  $}

  ${
    exp43.1 $e |- ( ( ( ph /\ ps ) /\ ( ch /\ th ) ) -> ta ) $.
    $( An exportation inference. $)
    exp43 $p |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $=
      ( wa exp exp4b ) ABCDEABGCDGEFHI $.
      $( [26-Apr-94] $)
  $}

  ${
    exp44.1 $e |- ( ( ph /\ ( ( ps /\ ch ) /\ th ) ) -> ta ) $.
    $( An exportation inference. $)
    exp44 $p |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $=
      ( wi wa exp32 exp3a ) ABCDEGABCHDEFIJ $.
      $( [26-Apr-94] $)
  $}

  ${
    exp45.1 $e |- ( ( ph /\ ( ps /\ ( ch /\ th ) ) ) -> ta ) $.
    $( An exportation inference. $)
    exp45 $p |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $=
      ( wa exp32 exp4a ) ABCDEABCDGEFHI $.
      $( [26-Apr-94] $)
  $}

  ${
    impac.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Importation with conjunction in consequent. $)
    impac $p |- ( ( ph /\ ps ) -> ( ch /\ ps ) ) $=
      ( wa ancrd imp ) ABCBEABCDFG $.
      $( [9-Aug-94] $)
  $}

  ${
    adantl.1 $e |- ( ph -> ps ) $.
    $( Inference adding a conjunct to the left of an antecedent. $)
    adantl $p |- ( ( ch /\ ph ) -> ps ) $=
      ( wi a1i imp ) CABABECDFG $.
      $( [30-Aug-93] $)
  $}

  ${
    adantr.1 $e |- ( ph -> ps ) $.
    $( Inference adding a conjunct to the right of an antecedent. $)
    adantr $p |- ( ( ph /\ ch ) -> ps ) $=
      ( a1d imp ) ACBABCDEF $.
      $( [30-Aug-93] $)
  $}

  ${
    adantld.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction adding a conjunct to the left of an antecedent. $)
    adantld $p |- ( ph -> ( ( th /\ ps ) -> ch ) ) $=
      ( wi a1d imp3a ) ADBCABCFDEGH $.
      $( [4-May-94] $)
  $}

  ${
    adantrd.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction adding a conjunct to the right of an antecedent. $)
    adantrd $p |- ( ph -> ( ( ps /\ th ) -> ch ) ) $=
      ( wa pm3.26 syl5 ) ABCBDFEBDGH $.
      $( [4-May-94] $)
  $}

  ${
    adant2.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    $( Deduction adding a conjunct to an antecedent. $)
    adantll $p |- ( ( ( th /\ ph ) /\ ps ) -> ch ) $=
      ( wa wi exp adantl imp ) DAFBCABCGDABCEHIJ $.
      $( [4-May-94] $)

    $( Deduction adding a conjunct to an antecedent. $)
    adantlr $p |- ( ( ( ph /\ th ) /\ ps ) -> ch ) $=
      ( wa wi exp adantr imp ) ADFBCABCGDABCEHIJ $.
      $( [4-May-94] $)

    $( Deduction adding a conjunct to an antecedent. $)
    adantrl $p |- ( ( ph /\ ( th /\ ps ) ) -> ch ) $=
      ( wa exp adantld imp ) ADBFCABCDABCEGHI $.
      $( [4-May-94] $)

    $( Deduction adding a conjunct to an antecedent. $)
    adantrr $p |- ( ( ph /\ ( ps /\ th ) ) -> ch ) $=
      ( wa exp adantrd imp ) ABDFCABCDABCEGHI $.
      $( [4-May-94] $)
  $}

  ${
    adantl2.1 $e |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $.
    $( Deduction adding a conjunct to an antecedent. $)
    adantlll $p |- ( ( ( ( ta /\ ph ) /\ ps ) /\ ch ) -> th ) $=
      ( wi exp31 a1i imp41 ) EABCDABCDGGGEABCDFHIJ $.
      $( [31-Dec-04] $)


    $( Deduction adding a conjunct to an antecedent. $)
    adantlrl $p |- ( ( ( ph /\ ( ta /\ ps ) ) /\ ch ) -> th ) $=
      ( wi exp31 a1d imp42 ) AEBCDABCDGGEABCDFHIJ $.
      $( [31-Dec-04] $) $( [26-Dec-04] $)

    $( Deduction adding a conjunct to an antecedent. $)
    adantlrr $p |- ( ( ( ph /\ ( ps /\ ta ) ) /\ ch ) -> th ) $=
      ( wi exp31 a1dd imp42 ) ABECDABCDGEABCDFHIJ $.
      $( [5-Jan-05] $) $( [26-Dec-04] $)
  $}

  ${
    adantr2.1 $e |- ( ( ph /\ ( ps /\ ch ) ) -> th ) $.
    $( Deduction adding a conjunct to an antecedent. $)
    adantrll $p |- ( ( ph /\ ( ( ta /\ ps ) /\ ch ) ) -> th ) $=
      ( wi exp32 a1d imp44 ) AEBCDABCDGGEABCDFHIJ $.
      $( [31-Dec-04] $) $( [26-Dec-04] $)

    $( Deduction adding a conjunct to an antecedent. $)
    adantrlr $p |- ( ( ph /\ ( ( ps /\ ta ) /\ ch ) ) -> th ) $=
      ( wi exp32 a1dd imp44 ) ABECDABCDGEABCDFHIJ $.
      $( [31-Dec-04] $) $( [26-Dec-04] $)

    $( Deduction adding a conjunct to an antecedent. $)
    adantrrl $p |- ( ( ph /\ ( ps /\ ( ta /\ ch ) ) ) -> th ) $=
      ( wi exp32 a1dd imp45 ) ABECDABCDGEABCDFHIJ $.
      $( [31-Dec-04] $) $( [26-Dec-04] $)

    $( Deduction adding a conjunct to an antecedent. $)
    adantrrr $p |- ( ( ph /\ ( ps /\ ( ch /\ ta ) ) ) -> th ) $=
      ( wi wa a1d exp32 imp45 ) ABCEDABCEDGABCHHDEFIJK $.
      $( [31-Dec-04] $) $( [26-Dec-04] $)
  $}

  ${
    ad2ant.1 $e |- ( ph -> ps ) $.

    $( Deduction adding conjuncts to an antecedent. $)
    ad2antll $p |- ( ( ( ph /\ ch ) /\ th ) -> ps ) $=
      ( wa adantr ) ACFBDABCEGG $.
      $( [19-Oct-99] $)

    $( Deduction adding conjuncts to an antecedent. $)
    ad2antlr $p |- ( ( ( ch /\ ph ) /\ th ) -> ps ) $=
      ( wa adantl adantr ) CAFBDABCEGH $.
      $( [19-Oct-99] $)

    $( Deduction adding conjuncts to an antecedent. $)
    ad2antrl $p |- ( ( ch /\ ( ph /\ th ) ) -> ps ) $=
      ( wa adantr adantl ) ADFBCABDEGH $.
      $( [19-Oct-99] $)

    $( Deduction adding conjuncts to an antecedent. $)
    ad2antrr $p |- ( ( ch /\ ( th /\ ph ) ) -> ps ) $=
      ( wa adantl ) DAFBCABDEGG $.
      $( [19-Oct-99] $)
  $}

  ${
    biimpa.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    $( Inference from a logical equivalence. $)
    biimpa $p |- ( ( ph /\ ps ) -> ch ) $=
      ( biimpd imp ) ABCABCDEF $.
      $( [3-May-94] $)

    $( Inference from a logical equivalence. $)
    biimpar $p |- ( ( ph /\ ch ) -> ps ) $=
      ( biimprd imp ) ACBABCDEF $.
      $( [3-May-94] $)

    $( Inference from a logical equivalence. $)
    biimpac $p |- ( ( ps /\ ph ) -> ch ) $=
      ( biimpcd imp ) BACABCDEF $.
      $( [3-May-94] $)

    $( Inference from a logical equivalence. $)
    biimparc $p |- ( ( ch /\ ph ) -> ps ) $=
      ( biimprcd imp ) CABABCDEF $.
      $( [3-May-94] $)
  $}

  $( Disjunction of antecedents.  Compare Theorem *4.77 of
     [WhiteheadRussell] p. 121. $)
  jaob $p |- ( ( ( ph \/ ch ) -> ps ) <-> ( ( ph -> ps ) /\ ( ch -> ps ) ) ) $=
    ( wo wi wa orc syl4 olc jca jao imp impbi ) ACDZBEZABEZCBEZFOPQANBACGHCNBCA
    IHJPQOABCKLM $.
    $( [30-May-94] $)


  ${
    jaod.1 $e |- ( ph -> ( ps -> ch ) ) $.
    jaod.2 $e |- ( ph -> ( th -> ch ) ) $.
    $( Deduction disjoining the antecedents of two implications. $)
    jaod $p |- ( ph -> ( ( ps \/ th ) -> ch ) ) $=
      ( wi wo jao sylc ) BCGDCGBDHCGABCDIEFJ $.
      $( [18-Aug-94] $)
  $}

  ${
    jaao.1 $e |- ( ph -> ( ps -> ch ) ) $.
    jaao.2 $e |- ( th -> ( ta -> ch ) ) $.
    $( Inference conjoining and disjoining the antecedents of two
       implications. $)
    jaao $p |- ( ( ph /\ th ) -> ( ( ps \/ ta ) -> ch ) ) $=
      ( wa wi adantr adantl jaod ) ADHBCEABCIDFJDECIAGKL $.
      $( [30-Sep-99] $)
  $}

  $( Idempotent law for conjunction.  Theorem *4.24 of [WhiteheadRussell]
     p. 117. $)
  anidm $p |- ( ( ph /\ ph ) <-> ph ) $=
    ( wa pm3.26 pm3.2 pm2.43i impbi ) AABZAAACAGAADEF $.
    $( [5-Aug-93] $)

  $( Theorem *4.24 of [WhiteheadRussell] p. 117. $)
  pm4.24 $p |-  ( ph <-> ( ph /\ ph ) ) $=
    ( wa anidm bicomi ) AABAACD $.
    $( [17-Jan-05] $) $( [3-Jan-05] $)

  ${
    anidms.1 $e |- ( ( ph /\ ph ) -> ps ) $.
    $( Inference from idempotent law for conjunction. $)
    anidms $p |- ( ph -> ps ) $=
      ( exp pm2.43i ) ABAABCDE $.
      $( [15-Jun-94] $)
  $}

  $( Commutative law for conjunction.  Theorem *4.3 of [WhiteheadRussell]
     p. 118. $)
  ancom $p |- ( ( ph /\ ps ) <-> ( ps /\ ph ) ) $=
    ( wa pm3.27 pm3.26 jca impbi ) ABCZBACZHBAABDABEFIABBADBAEFG $.
    $( [25-Jun-98] $)

  ${
    ancoms.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    $( Inference commuting conjunction in antecedent.  _Notational convention_:
       We sometimes suffix with "s" the label of an inference that manipulates
       an antecedent, leaving the consequent unchanged.  The "s" means that the
       inference eliminates the need for a syllogism ( ~ syl ) -type inference
       in a proof. $)
    ancoms $p |- ( ( ps /\ ph ) -> ch ) $=
      ( wa ancom sylbi ) BAEABECBAFDG $.
      $( [21-Apr-94] $)
  $}

  ${
    ancomsd.1 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    $( Deduction commuting conjunction in antecedent. $)
    ancomsd $p |- ( ph -> ( ( ch /\ ps ) -> th ) ) $=
      ( wa ancom syl5ib ) ABCFDCBFECBGH $.
      $( [13-Dec-04] $) $( [12-Dec-04] $)
  $}

  $( Theorem *3.22 of [WhiteheadRussell] p. 111. $)
  pm3.22 $p |-  ( ( ph /\ ps ) -> ( ps /\ ph ) ) $=
    ( wa ancom biimp ) ABCBACABDE $.
    $( [17-Jan-05] $) $( [3-Jan-05] $)

  $( Associative law for conjunction.  Theorem *4.32 of [WhiteheadRussell]
     p. 118. $)
  anass $p |- ( ( ( ph /\ ps ) /\ ch ) <-> ( ph /\ ( ps /\ ch ) ) ) $=
    ( wa wn wi impexp imnan imbi2i bitr negbii df-an 3bitr4 ) ABDZCEZFZEABCDZEZ
    FZENCDAQDPSPABOFZFSABOGTRABCHIJKNCLAQLM $.
    $( [5-Aug-93] $)

  ${
    anasss.1 $e |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $.
    $( Associative law for conjunction applied to antecedent (eliminates
       syllogism). $)
    anasss $p |- ( ( ph /\ ( ps /\ ch ) ) -> th ) $=
      ( exp31 imp32 ) ABCDABCDEFG $.
      $( [15-Nov-02] $)
  $}

  ${
    anassrs.1 $e |- ( ( ph /\ ( ps /\ ch ) ) -> th ) $.
    $( Associative law for conjunction applied to antecedent (eliminates
       syllogism). $)
    anassrs $p |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $=
      ( exp32 imp31 ) ABCDABCDEFG $.
      $( [15-Nov-02] $)
  $}

  $( Distribution of implication with conjunction. $)
  imdistan $p |- ( ( ph -> ( ps -> ch ) ) <->
                 ( ( ph /\ ps ) -> ( ph /\ ch ) ) ) $=
    ( wi wa anc2l imp3a pm3.27 syl3 exp3a impbi ) ABCDDZABEZACEZDZLABNABCFGOABC
    NCMACHIJK $.
    $( [31-May-99] $)

  ${
    imdistani.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Distribution of implication with conjunction. $)
    imdistani $p |- ( ( ph /\ ps ) -> ( ph /\ ch ) ) $=
      ( wa anc2li imp ) ABACEABCDFG $.
      $( [1-Aug-94] $)
  $}

  ${
    imdistanri.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Distribution of implication with conjunction. $)
    imdistanri $p |- ( ( ps /\ ph ) -> ( ch /\ ph ) ) $=
      ( com12 impac ) BACABCDEF $.
      $( [8-Jan-02] $)
  $}

  ${
    imdistand.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    $( Distribution of implication with conjunction (deduction rule). $)
    imdistand $p |- ( ph -> ( ( ps /\ ch ) -> ( ps /\ th ) ) ) $=
      ( wi wa imdistan sylib ) ABCDFFBCGBDGFEBCDHI $.
      $( [28-Aug-04] $) $( [27-Aug-04] $)
  $}

  ${
    sylan.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    ${
      sylan.2 $e |- ( th -> ph ) $.
      $( A syllogism inference. $)
      sylan $p |- ( ( th /\ ps ) -> ch ) $=
        ( wi exp syl imp ) DBCDABCGFABCEHIJ $.
        $( [21-Apr-94] $)
    $}

    ${
      sylanb.2 $e |- ( th <-> ph ) $.
      $( A syllogism inference. $)
      sylanb $p |- ( ( th /\ ps ) -> ch ) $=
        ( biimp sylan ) ABCDEDAFGH $.
        $( [18-May-94] $)
    $}

    ${
      sylanbr.2 $e |- ( ph <-> th ) $.
      $( A syllogism inference. $)
      sylanbr $p |- ( ( th /\ ps ) -> ch ) $=
        ( biimpr sylan ) ABCDEADFGH $.
        $( [18-May-94] $)
    $}

    ${
      sylan2.2 $e |- ( th -> ps ) $.
      $( A syllogism inference. $)
      sylan2 $p |- ( ( ph /\ th ) -> ch ) $=
        ( exp syl5 imp ) ADCABCDABCEGFHI $.
        $( [21-Apr-94] $)
    $}

    ${
      sylan2b.2 $e |- ( th <-> ps ) $.
      $( A syllogism inference. $)
      sylan2b $p |- ( ( ph /\ th ) -> ch ) $=
        ( biimp sylan2 ) ABCDEDBFGH $.
        $( [21-Apr-94] $)
    $}

    ${
      sylan2br.2 $e |- ( ps <-> th ) $.
      $( A syllogism inference. $)
      sylan2br $p |- ( ( ph /\ th ) -> ch ) $=
        ( biimpr sylan2 ) ABCDEBDFGH $.
        $( [21-Apr-94] $)
    $}

    ${
      syl2an.2 $e |- ( th -> ph ) $.
      syl2an.3 $e |- ( ta -> ps ) $.
      $( A double syllogism inference. $)
      syl2an $p |- ( ( th /\ ta ) -> ch ) $=
        ( sylan sylan2 ) DBCEABCDFGIHJ $.
        $( [31-Jan-97] $)
    $}

    ${
      syl2anb.2 $e |- ( th <-> ph ) $.
      syl2anb.3 $e |- ( ta <-> ps ) $.
      $( A double syllogism inference. $)
      syl2anb $p |- ( ( th /\ ta ) -> ch ) $=
        ( sylanb sylan2b ) DBCEABCDFGIHJ $.
        $( [29-Jul-99] $)
    $}

    ${
      syl2anbr.2 $e |- ( ph <-> th ) $.
      syl2anbr.3 $e |- ( ps <-> ta ) $.
      $( A double syllogism inference. $)
      syl2anbr $p |- ( ( th /\ ta ) -> ch ) $=
        ( sylanbr sylan2br ) DBCEABCDFGIHJ $.
        $( [29-Jul-99] $)
    $}
  $}

  ${
    syland.1 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    syland.2 $e |- ( ph -> ( ta -> ps ) ) $.
    $( A syllogism deduction. $)
    syland $p |- ( ph -> ( ( ta /\ ch ) -> th ) ) $=
      ( wi exp3a syld imp3a ) AECDAEBCDHGABCDFIJK $.
      $( [17-Dec-04] $) $( [15-Dec-04] $)
  $}

  ${
    sylan2d.1 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    sylan2d.2 $e |- ( ph -> ( ta -> ch ) ) $.
    $( A syllogism deduction. $)
    sylan2d $p |- ( ph -> ( ( ps /\ ta ) -> th ) ) $=
      ( ancomsd syland ) AEBDACBDEABCDFHGIH $.
      $( [17-Dec-04] $) $( [15-Dec-04] $)
  $}

  ${
    $v et $. $( Greek eta $)
    syl2and.wet $f wff et $.
    syl2and.1 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    syl2and.2 $e |- ( ph -> ( ta -> ps ) ) $.
    syl2and.3 $e |- ( ph -> ( et -> ch ) ) $.
    $( A syllogism deduction. $)
    syl2and $p |- ( ph -> ( ( ta /\ et ) -> th ) ) $=
      ( sylan2d syland ) ABFDEABCDFGIJHK $.
      $( [17-Dec-04] $) $( [15-Dec-04] $)
  $}

  ${
    sylan11.1 $e |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $.
    sylan11.2 $e |- ( ta -> ph ) $.
  $}

  ${
    sylan12.1 $e |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $.
    sylan12.2 $e |- ( ta -> ps ) $.
    $( A syllogism inference. $)
    sylan12 $p |- ( ( ( ph /\ ta ) /\ ch ) -> th ) $=
      ( wa anim2i sylan ) ABHCDAEHFEBAGIJ $.
      $( [2-Jan-05] $) $( [1-Jan-05] $)
  $}

  ${
    sylani.1 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    sylani.2 $e |- ( ta -> ps ) $.
    $( A syllogism inference. $)
    sylani $p |- ( ph -> ( ( ta /\ ch ) -> th ) ) $=
      ( wi a1i syland ) ABCDEFEBHAGIJ $.
      $( [2-May-96] $)
  $}

  ${
    sylan2i.1 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    sylan2i.2 $e |- ( ta -> ch ) $.
    $( A syllogism inference. $)
    sylan2i $p |- ( ph -> ( ( ps /\ ta ) -> th ) ) $=
      ( wi a1i sylan2d ) ABCDEFECHAGIJ $.
      $( [1-Aug-94] $)
  $}

  ${
    $v et $. $( Greek eta $)
    syl2ani.wet $f wff et $.
    syl2ani.1 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    syl2ani.2 $e |- ( ta -> ps ) $.
    syl2ani.3 $e |- ( et -> ch ) $.
    $( A syllogism inference. $)
    syl2ani $p |- ( ph -> ( ( ta /\ et ) -> th ) ) $=
      ( sylan2i sylani ) ABFDEABCDFGIJHK $.
      $( [3-Aug-99] $)
  $}

  ${
    syldan.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    syldan.2 $e |- ( ( ph /\ ch ) -> th ) $.
    $( A syllogism deduction with conjoined antecents. $)
    syldan $p |- ( ( ph /\ ps ) -> th ) $=
      ( exp syld imp ) ABDABCDABCEGACDFGHI $.
      $( [26-Feb-05] $) $( [24-Feb-05] $)
  $}

  ${
    sylan9.1 $e |- ( ph -> ( ps -> ch ) ) $.
    sylan9.2 $e |- ( th -> ( ch -> ta ) ) $.
    $( Nested syllogism inference conjoining dissimilar antecedents. $)
    sylan9 $p |- ( ( ph /\ th ) -> ( ps -> ta ) ) $=
      ( wa wi adantr adantl syld ) ADHBCEABCIDFJDCEIAGKL $.
      $( [5-Aug-93] $)
  $}

  ${
    sylan9r.1 $e |- ( ph -> ( ps -> ch ) ) $.
    sylan9r.2 $e |- ( th -> ( ch -> ta ) ) $.
    $( Nested syllogism inference conjoining dissimilar antecedents. $)
    sylan9r $p |- ( ( th /\ ph ) -> ( ps -> ta ) ) $=
      ( wi syl9r imp ) DABEHABCDEFGIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    sylanc.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    sylanc.2 $e |- ( th -> ph ) $.
    sylanc.3 $e |- ( th -> ps ) $.
    $( A syllogism inference combined with contraction. $)
    sylanc $p |- ( th -> ch ) $=
      ( exp sylc ) ABCDABCEHFGI $.
      $( [3-Oct-99] $)
  $}

  ${
    sylancb.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    sylancb.2 $e |- ( th <-> ph ) $.
    sylancb.3 $e |- ( th <-> ps ) $.
    $( A syllogism inference combined with contraction. $)
    sylancb $p |- ( th -> ch ) $=
      ( syl2anb anidms ) DCABCDDEFGHI $.
      $( [9-Sep-04] $) $( [3-Sep-04] $)
  $}

  ${
    sylancbr.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    sylancbr.2 $e |- ( ph <-> th ) $.
    sylancbr.3 $e |- ( ps <-> th ) $.
    $( A syllogism inference combined with contraction. $)
    sylancbr $p |- ( th -> ch ) $=
      ( syl2anbr anidms ) DCABCDDEFGHI $.
      $( [14-Sep-04] $) $( [3-Sep-04] $)
  $}

  ${
    pm2.61an1.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    pm2.61an1.2 $e |- ( ( -. ph /\ ps ) -> ch ) $.
    $( Elimination of an antecedent. $)
    pm2.61an1 $p |- ( ps -> ch ) $=
      ( wi exp wn pm2.61i ) ABCFABCDGAHBCEGI $.
      $( [3-Jan-05] $) $( [1-Jan-05] $)
  $}

  ${
    pm2.61an2.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    pm2.61an2.2 $e |- ( ( ph /\ -. ps ) -> ch ) $.
    $( Elimination of an antecedent. $)
    pm2.61an2 $p |- ( ph -> ch ) $=
      ( exp wn pm2.61d ) ABCABCDFABGCEFH $.
      $( [3-Jan-05] $) $( [1-Jan-05] $)
  $}

  $( Introduce one conjunct as an antecedent to the another. $)
  abai $p |- ( ( ph /\ ps ) <-> ( ph /\ ( ph -> ps ) ) ) $=
    ( wa wi pm3.26 pm3.4 jca pm3.35 impbi ) ABCZAABDZCZJAKABEABFGLABAKEABHGI $.
    $( [12-Aug-93] $)

  ${
    bi.aa $e |- ( ph <-> ps ) $.

    $( Introduce a left conjunct to both sides of a logical equivalence. $)
    anbi2i $p |- ( ( ch /\ ph ) <-> ( ch /\ ps ) ) $=
      ( wa biimp anim2i biimpr impbi ) CAECBEABCABDFGBACABDHGI $.
      $( [5-Aug-93] $)

    $( Introduce a right conjunct to both sides of a logical equivalence. $)
    anbi1i $p |- ( ( ph /\ ch ) <-> ( ps /\ ch ) ) $=
      ( wa ancom anbi2i 3bitr ) ACECAECBEBCEACFABCDGCBFH $.
      $( [5-Aug-93] $)
  $}

  ${
    bi2an.1 $e |- ( ph <-> ps ) $.
    bi2an.2 $e |- ( ch <-> th ) $.
    $( Conjoin both sides of two equivalences. $)
    anbi12i $p |- ( ( ph /\ ch ) <-> ( ps /\ th ) ) $=
      ( wa anbi1i anbi2i bitr ) ACGBCGBDGABCEHCDBFIJ $.
      $( [5-Aug-93] $)
  $}

  $( A rearrangement of conjuncts. $)
  an12 $p |- ( ( ph /\ ( ps /\ ch ) ) <-> ( ps /\ ( ph /\ ch ) ) ) $=
    ( wa ancom anbi1i anass 3bitr3 ) ABDZCDBADZCDABCDDBACDDIJCABEFABCGBACGH $.
    $( [12-Mar-95] $)

  $( A rearrangement of conjuncts. $)
  an23 $p |- ( ( ( ph /\ ps ) /\ ch ) <-> ( ( ph /\ ch ) /\ ps ) ) $=
    ( wa ancom anbi2i anass 3bitr4 ) ABCDZDACBDZDABDCDACDBDIJABCEFABCGACBGH $.
    $( [12-Mar-95] $)

  ${
    an1s.1 $e |- ( ( ph /\ ( ps /\ ch ) ) -> th ) $.
    $( Deduction rearranging conjuncts. $)
    an1s $p |- ( ( ps /\ ( ph /\ ch ) ) -> th ) $=
      ( wa an12 sylbi ) BACFFABCFFDBACGEH $.
      $( [13-Mar-96] $)
  $}

  ${
    an1rs.1 $e |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $.
    $( Deduction rearranging conjuncts. $)
    an1rs $p |- ( ( ( ph /\ ch ) /\ ps ) -> th ) $=
      ( wa an23 sylbi ) ACFBFABFCFDACBGEH $.
      $( [13-Mar-96] $)
  $}

  $( Absorption into embedded conjunct. $)
  anabs1 $p |- ( ( ( ph /\ ps ) /\ ph ) <-> ( ph /\ ps ) ) $=
    ( wa pm3.26 id jca impbi ) ABCZACHHADHHAHEABDFG $.
    $( [4-Sep-95] $)

  $( Absorption into embedded conjunct. $)
  anabs5 $p |- ( ( ph /\ ( ph /\ ps ) ) <-> ( ph /\ ps ) ) $=
    ( wa ancom anabs1 bitr3 ) AABCZCGACGGADABEF $.
    $( [20-Jul-96] $)

  $( Absorption into embedded conjunct. $)
  anabs7 $p |- ( ( ps /\ ( ph /\ ps ) ) <-> ( ph /\ ps ) ) $=
    ( wa pm3.27 id jca impbi ) BABCZCHBHDHBHABDHEFG $.
    $( [20-Jul-96] $)

  ${
    anabsi5.1 $e |- ( ph -> ( ( ph /\ ps ) -> ch ) ) $.
    $( Absorption of antecedent into conjunction. $)
    anabsi5 $p |- ( ( ph /\ ps ) -> ch ) $=
      ( wa wi adantr pm2.43i ) ABEZCAICFBDGH $.
      $( [11-Jun-95] $)
  $}

  ${
    anabsi6.1 $e |- ( ph -> ( ( ps /\ ph ) -> ch ) ) $.
    $( Absorption of antecedent into conjunction. $)
    anabsi6 $p |- ( ( ph /\ ps ) -> ch ) $=
      ( ancomsd anabsi5 ) ABCABACDEF $.
      $( [14-Aug-00] $)
  $}

  ${
    anabsi7.1 $e |- ( ps -> ( ( ph /\ ps ) -> ch ) ) $.
    $( Absorption of antecedent into conjunction. $)
    anabsi7 $p |- ( ( ph /\ ps ) -> ch ) $=
      ( exp3a pm2.43b imp ) ABCABCBABCDEFG $.
      $( [20-Jul-96] $)
  $}

  ${
    anabsi8.1 $e |- ( ps -> ( ( ps /\ ph ) -> ch ) ) $.
    $( Absorption of antecedent into conjunction. $)
    anabsi8 $p |- ( ( ph /\ ps ) -> ch ) $=
      ( anabsi5 ancoms ) BACBACDEF $.
      $( [26-Sep-99] $)
  $}

  ${
    anabss1.1 $e |- ( ( ( ph /\ ps ) /\ ph ) -> ch ) $.
    $( Absorption of antecedent into conjunction. $)
    anabss1 $p |- ( ( ph /\ ps ) -> ch ) $=
      ( wa adantrr anidms ) ABEZCHACBDFG $.
      $( [20-Jul-96] $)
  $}

  ${
    anabss3.1 $e |- ( ( ( ph /\ ps ) /\ ps ) -> ch ) $.
    $( Absorption of antecedent into conjunction. $)
    anabss3 $p |- ( ( ph /\ ps ) -> ch ) $=
      ( wa adantrl anidms ) ABEZCHBCADFG $.
      $( [20-Jul-96] $)
  $}

  ${
    anabss4.1 $e |- ( ( ( ps /\ ph ) /\ ps ) -> ch ) $.
    $( Absorption of antecedent into conjunction. $)
    anabss4 $p |- ( ( ph /\ ps ) -> ch ) $=
      ( anabss1 ancoms ) BACBACDEF $.
      $( [20-Jul-96] $)
  $}

  ${
    anabss5.1 $e |- ( ( ph /\ ( ph /\ ps ) ) -> ch ) $.
    $( Absorption of antecedent into conjunction. $)
    anabss5 $p |- ( ( ph /\ ps ) -> ch ) $=
      ( wa adantlr anidms ) ABEZCAHCBDFG $.
      $( [10-May-94] $)
  $}

  ${
    anabss7.1 $e |- ( ( ps /\ ( ph /\ ps ) ) -> ch ) $.
    $( Absorption of antecedent into conjunction. $)
    anabss7 $p |- ( ( ph /\ ps ) -> ch ) $=
      ( wa exp anabsi7 ) ABCBABECDFG $.
      $( [20-Jul-96] $)
  $}

  ${
    anabsan.1 $e |- ( ( ( ph /\ ph ) /\ ps ) -> ch ) $.
    $( Absorption of antecedent with conjunction. $)
    anabsan $p |- ( ( ph /\ ps ) -> ch ) $=
      ( an1rs anabss1 ) ABCAABCDEF $.
      $( [24-Mar-96] $)
  $}

  ${
    anabsan2.1 $e |- ( ( ph /\ ( ps /\ ps ) ) -> ch ) $.
    $( Absorption of antecedent with conjunction. $)
    anabsan2 $p |- ( ( ph /\ ps ) -> ch ) $=
      ( anassrs anabss3 ) ABCABBCDEF $.
      $( [10-May-04] $) $( [10-May-04] $)
  $}

  $( Rearrangement of 4 conjuncts. $)
  an4 $p |- ( ( ( ph /\ ps ) /\ ( ch /\ th ) ) <->
              ( ( ph /\ ch ) /\ ( ps /\ th ) ) ) $=
    ( wa an12 anbi2i anass 3bitr4 ) ABCDEZEZEACBDEZEZEABEJEACELEKMABCDFGABJHACL
    HI $.
    $( [10-Jul-94] $)

  $( Rearrangement of 4 conjuncts. $)
  an42 $p |- ( ( ( ph /\ ps ) /\ ( ch /\ th ) ) <->
                 ( ( ph /\ ch ) /\ ( th /\ ps ) ) ) $=
    ( wa an4 ancom anbi2i bitr ) ABECDEEACEZBDEZEJDBEZEABCDFKLJBDGHI $.
    $( [7-Feb-96] $)

  ${
    an4s.1 $e |- ( ( ( ph /\ ps ) /\ ( ch /\ th ) ) -> ta ) $.
    $( Inference rearranging 4 conjuncts in antecedent. $)
    an4s $p |- ( ( ( ph /\ ch ) /\ ( ps /\ th ) ) -> ta ) $=
      ( wa an4 sylbi ) ACGBDGGABGCDGGEACBDHFI $.
      $( [10-Aug-95] $)
  $}

  ${
    an41r3s.1 $e |- ( ( ( ph /\ ps ) /\ ( ch /\ th ) ) -> ta ) $.
    $( Inference rearranging 4 conjuncts in antecedent. $)
    an42s $p |- ( ( ( ph /\ ch ) /\ ( th /\ ps ) ) -> ta ) $=
      ( wa an42 sylbir ) ACGDBGGABGCDGGEABCDHFI $.
      $( [10-Aug-95] $)
  $}

  $( Distribution of conjunction over conjunction. $)
  anandi $p |- ( ( ph /\ ( ps /\ ch ) ) <->
               ( ( ph /\ ps ) /\ ( ph /\ ch ) ) ) $=
    ( wa anidm anbi1i an4 bitr3 ) ABCDZDAADZIDABDACDDJAIAEFAABCGH $.
    $( [14-Aug-95] $)

  $( Distribution of conjunction over conjunction. $)
  anandir $p |- ( ( ( ph /\ ps ) /\ ch ) <->
               ( ( ph /\ ch ) /\ ( ps /\ ch ) ) ) $=
    ( wa anidm anbi2i an4 bitr3 ) ABDZCDICCDZDACDBCDDJCICEFABCCGH $.
    $( [24-Aug-95] $)

  ${
    anandis.1 $e |- ( ( ( ph /\ ps ) /\ ( ph /\ ch ) ) -> ta ) $.
    $( Inference that undistributes conjunction in the antecedent. $)
    anandis $p |- ( ( ph /\ ( ps /\ ch ) ) -> ta ) $=
      ( wa an4s anabsan ) ABCFDABACDEGH $.
      $( [7-Jun-04] $) $( [7-Jun-04] $)
  $}

  ${
    anandirs.1 $e |- ( ( ( ph /\ ch ) /\ ( ps /\ ch ) ) -> ta ) $.
    $( Inference that undistributes conjunction in the antecedent. $)
    anandirs $p |- ( ( ( ph /\ ps ) /\ ch ) -> ta ) $=
      ( wa an4s anabsan2 ) ABFCDACBCDEGH $.
      $( [8-Jun-04] $) $( [7-Jun-04] $)
  $}

  $( A theorem similar to the standard definition of the biconditional.
     Definition of [Margaris] p. 49. $)
  bi $p |- ( ( ph <-> ps ) <-> ( ( ph -> ps ) /\ ( ps -> ph ) ) ) $=
    ( wb wi wn wa bii df-an bitr4 ) ABCABDZBADZEDEJKFABGJKHI $.
    $( [5-Aug-93] $)

  ${
    impbid.1 $e |- ( ph -> ( ps -> ch ) ) $.
    impbid.2 $e |- ( ph -> ( ch -> ps ) ) $.
    $( Deduce an equivalence from two implications. $)
    impbid $p |- ( ph -> ( ps <-> ch ) ) $=
      ( wi wa wb jca bi sylibr ) ABCFZCBFZGBCHALMDEIBCJK $.
      $( [5-Aug-93] $)
  $}

  $( Commutative law for equivalence.  Theorem *4.21 of [WhiteheadRussell]
     p. 117. $)
  bicom $p |- ( ( ph <-> ps ) <-> ( ps <-> ph ) ) $=
    ( wi wa wb ancom bi 3bitr4 ) ABCZBACZDJIDABEBAEIJFABGBAGH $.
    $( [5-Aug-93] $)

  ${
    bicomd.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    $( Commute two sides of a biconditional in a deduction. $)
    bicomd $p |- ( ph -> ( ch <-> ps ) ) $=
      ( wb bicom sylib ) ABCECBEDBCFG $.
      $( [5-Aug-93] $)
  $}

  $( Contraposition.  Theorem *4.11 of [WhiteheadRussell] p. 117. $)
  pm4.11 $p |- ( ( ph <-> ps ) <-> ( -. ph <-> -. ps ) ) $=
    ( wb wn wi wa pm4.1 anbi12i bi 3bitr4 bicom bitr ) ABCZBDZADZCZONCABEZBAEZF
    NOEZONEZFMPQSRTABGBAGHABINOIJNOKL $.
    $( [21-May-94] $)

  ${
    bicon4.1 $e |- ( -. ph <-> -. ps ) $.
    $( A contraposition inference. $)
    bicon4i $p |- ( ph <-> ps ) $=
      ( wb wn pm4.11 mpbir ) ABDAEBEDCABFG $.
      $( [21-May-94] $)
  $}

  ${
    bicon4d.1 $e |- ( ph -> ( -. ps <-> -. ch ) ) $.
    $( A contraposition deduction. $)
    bicon4d $p |- ( ph -> ( ps <-> ch ) ) $=
      ( wn wb pm4.11 sylibr ) ABECEFBCFDBCGH $.
      $( [21-May-94] $)
  $}

  $( Contraposition.  Theorem *4.12 of [WhiteheadRussell] p. 117. $)
  bicon2 $p |- ( ( ph <-> -. ps ) <-> ( ps <-> -. ph ) ) $=
    ( wn wi wa wb bi2.03 bi2.15 anbi12i bi 3bitr4 ) ABCZDZLADZEBACZDZOBDZEALFBO
    FMPNQABGBAHIALJBOJK $.
    $( [15-Apr-95] $)

  ${
    bicon2d.1 $e |- ( ph -> ( ps <-> -. ch ) ) $.
    $( A contraposition deduction. $)
    bicon2d $p |- ( ph -> ( ch <-> -. ps ) ) $=
      ( wn wb bicon2 sylibr ) ABCEFCBEFDCBGH $.
      $( [15-Apr-95] $)
  $}

  ${
    bicon1d.1 $e |- ( ph -> ( -. ps <-> ch ) ) $.
    $( A contraposition deduction. $)
    bicon1d $p |- ( ph -> ( -. ch <-> ps ) ) $=
      ( wn bicomd bicon2d ) ABCEACBABECDFGF $.
      $( [9-Oct-99] $)
  $}

  ${
    bitrd.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    bitrd.2 $e |- ( ph -> ( ch <-> th ) ) $.
    $( Deduction form of ~ bitr . $)
    bitrd $p |- ( ph -> ( ps <-> th ) ) $=
      ( biimpd sylibd biimprd sylibrd impbid ) ABDABCDABCEGFHADCBACDFIEJK $.
      $( [5-Aug-93] $)
  $}

  ${
    bitr2d.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    bitr2d.2 $e |- ( ph -> ( ch <-> th ) ) $.
    $( Deduction form of ~ bitr2 . $)
    bitr2d $p |- ( ph -> ( th <-> ps ) ) $=
      ( bitrd bicomd ) ABDABCDEFGH $.
      $( [11-Jun-04] $) $( [9-Jun-04] $)
  $}

  ${
    bitr3d.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    bitr3d.2 $e |- ( ph -> ( ps <-> th ) ) $.
    $( Deduction form of ~ bitr3 . $)
    bitr3d $p |- ( ph -> ( ch <-> th ) ) $=
      ( bicomd bitrd ) ACBDABCEGFH $.
      $( [5-Aug-93] $)
  $}

  ${
    bitr4d.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    bitr4d.2 $e |- ( ph -> ( th <-> ch ) ) $.
    $( Deduction form of ~ bitr4 . $)
    bitr4d $p |- ( ph -> ( ps <-> th ) ) $=
      ( bicomd bitrd ) ABCDEADCFGH $.
      $( [5-Aug-93] $)
  $}

  ${
    syl5bb.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl5bb.2 $e |- ( th <-> ps ) $.
    $( A syllogism inference from two biconditionals. $)
    syl5bb $p |- ( ph -> ( th <-> ch ) ) $=
      ( wb a1i bitrd ) ADBCDBGAFHEI $.
      $( [5-Aug-93] $)
  $}

  ${
    syl5rbb.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl5rbb.2 $e |- ( th <-> ps ) $.
    $( A syllogism inference from two biconditionals. $)
    syl5rbb $p |- ( ph -> ( ch <-> th ) ) $=
      ( syl5bb bicomd ) ADCABCDEFGH $.
      $( [5-Aug-93] $)
  $}

  ${
    syl5bbr.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl5bbr.2 $e |- ( ps <-> th ) $.
    $( A syllogism inference from two biconditionals. $)
    syl5bbr $p |- ( ph -> ( th <-> ch ) ) $=
      ( bicomi syl5bb ) ABCDEBDFGH $.
      $( [5-Aug-93] $)
  $}

  ${
    syl5rbbr.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl5rbbr.2 $e |- ( ps <-> th ) $.
    $( A syllogism inference from two biconditionals. $)
    syl5rbbr $p |- ( ph -> ( ch <-> th ) ) $=
      ( bicomi syl5rbb ) ABCDEBDFGH $.
      $( [25-Nov-94] $)
  $}

  ${
    syl6bb.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl6bb.2 $e |- ( ch <-> th ) $.
    $( A syllogism inference from two biconditionals. $)
    syl6bb $p |- ( ph -> ( ps <-> th ) ) $=
      ( wb a1i bitrd ) ABCDECDGAFHI $.
      $( [5-Aug-93] $)
  $}

  ${
    syl6rbb.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl6rbb.2 $e |- ( ch <-> th ) $.
    $( A syllogism inference from two biconditionals. $)
    syl6rbb $p |- ( ph -> ( th <-> ps ) ) $=
      ( syl6bb bicomd ) ABDABCDEFGH $.
      $( [5-Aug-93] $)
  $}

  ${
    syl6bbr.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl6bbr.2 $e |- ( th <-> ch ) $.
    $( A syllogism inference from two biconditionals. $)
    syl6bbr $p |- ( ph -> ( ps <-> th ) ) $=
      ( bicomi syl6bb ) ABCDEDCFGH $.
      $( [5-Aug-93] $)
  $}

  ${
    syl6rbbr.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl6rbbr.2 $e |- ( th <-> ch ) $.
    $( A syllogism inference from two biconditionals. $)
    syl6rbbr $p |- ( ph -> ( th <-> ps ) ) $=
      ( bicomi syl6rbb ) ABCDEDCFGH $.
      $( [25-Nov-94] $)
  $}

  ${
    sylan9bb.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    sylan9bb.2 $e |- ( th -> ( ch <-> ta ) ) $.
    $( Nested syllogism inference conjoining dissimilar antecedents. $)
    sylan9bb $p |- ( ( ph /\ th ) -> ( ps <-> ta ) ) $=
      ( wa wb adantr adantl bitrd ) ADHBCEABCIDFJDCEIAGKL $.
      $( [4-Mar-95] $)
  $}

  ${
    sylan9bbr.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    sylan9bbr.2 $e |- ( th -> ( ch <-> ta ) ) $.
    $( Nested syllogism inference conjoining dissimilar antecedents. $)
    sylan9bbr $p |- ( ( th /\ ph ) -> ( ps <-> ta ) ) $=
      ( wb sylan9bb ancoms ) ADBEHABCDEFGIJ $.
      $( [4-Mar-95] $)
  $}

  ${
    3imtr3d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    3imtr3d.2 $e |- ( ph -> ( ps <-> th ) ) $.
    3imtr3d.3 $e |- ( ph -> ( ch <-> ta ) ) $.
    $( More general version of ~ 3imtr3 .  Useful for converting
       conditional definitions in a formula. $)
    3imtr3d $p |- ( ph -> ( th -> ta ) ) $=
      ( sylibd sylbird ) ADBEGABCEFHIJ $.
      $( [8-Apr-96] $)
  $}

  ${
    3imtr4d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    3imtr4d.2 $e |- ( ph -> ( th <-> ps ) ) $.
    3imtr4d.3 $e |- ( ph -> ( ta <-> ch ) ) $.
    $( More general version of ~ 3imtr4 .  Useful for converting
       conditional definitions in a formula. $)
    3imtr4d $p |- ( ph -> ( th -> ta ) ) $=
      ( sylibrd sylbid ) ADBEGABCEFHIJ $.
      $( [26-Oct-95] $)
  $}

  ${
    3bitrd.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    3bitrd.2 $e |- ( ph -> ( ch <-> th ) ) $.
    3bitrd.3 $e |- ( ph -> ( th <-> ta ) ) $.
    $( Deduction from transitivity of biconditional. $)
    3bitrd $p |- ( ph -> ( ps <-> ta ) ) $=
      ( bitrd ) ABDEABCDFGIHI $.
      $( [13-Aug-99] $)
  $}

  ${
    3bitr3d.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    3bitr3d.2 $e |- ( ph -> ( ps <-> th ) ) $.
    3bitr3d.3 $e |- ( ph -> ( ch <-> ta ) ) $.
    $( Deduction from transitivity of biconditional.  Useful for converting
       conditional definitions in a formula. $)
    3bitr3d $p |- ( ph -> ( th <-> ta ) ) $=
      ( bitr3d bitrd ) ADCEABDCGFIHJ $.
      $( [24-Apr-96] $)
  $}

  ${
    3bitr4d.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    3bitr4d.2 $e |- ( ph -> ( th <-> ps ) ) $.
    3bitr4d.3 $e |- ( ph -> ( ta <-> ch ) ) $.
    $( Deduction from transitivity of biconditional.  Useful for converting
       conditional definitions in a formula. $)
    3bitr4d $p |- ( ph -> ( th <-> ta ) ) $=
      ( bitr4d bitrd ) ADBEGABCEFHIJ $.
      $( [18-Oct-95] $)
  $}

  ${
    3imtr3g.1 $e |- ( ph -> ( ps -> ch ) ) $.
    3imtr3g.2 $e |- ( ps <-> th ) $.
    3imtr3g.3 $e |- ( ch <-> ta ) $.
    $( More general version of ~ 3imtr3 .  Useful for converting
       definitions in a formula. $)
    3imtr3g $p |- ( ph -> ( th -> ta ) ) $=
      ( wa imp anbi2i 3imtr3 exp ) ADEABICADIEABCFJBDAGKHLM $.
      $( [20-May-96] $)
  $}

  ${
    3imtr4g.1 $e |- ( ph -> ( ps -> ch ) ) $.
    3imtr4g.2 $e |- ( th <-> ps ) $.
    3imtr4g.3 $e |- ( ta <-> ch ) $.
    $( More general version of ~ 3imtr4 .  Useful for converting
       definitions in a formula. $)
    3imtr4g $p |- ( ph -> ( th -> ta ) ) $=
      ( bicomi 3imtr3g ) ABCDEFDBGIECHIJ $.
      $( [20-May-96] $)
  $}

  ${
    3bitr3g.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    3bitr3g.2 $e |- ( ps <-> th ) $.
    3bitr3g.3 $e |- ( ch <-> ta ) $.
    $( More general version of ~ 3bitr3 .  Useful for converting
       definitions in a formula. $)
    3bitr3g $p |- ( ph -> ( th <-> ta ) ) $=
      ( syl5bbr syl6bb ) ADCEABCDFGIHJ $.
      $( [4-Jun-95] $)
  $}

  ${
    3bitr4g.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    3bitr4g.2 $e |- ( th <-> ps ) $.
    3bitr4g.3 $e |- ( ta <-> ch ) $.
    $( More general version of ~ 3bitr4 .  Useful for converting
       definitions in a formula. $)
    3bitr4g $p |- ( ph -> ( th <-> ta ) ) $=
      ( syl5bb syl6bbr ) ADCEABCDFGIHJ $.
      $( [5-Aug-93] $)
  $}

  $( Theorem *3.47 of [WhiteheadRussell] p. 113.  It was proved by Leibniz, and
     it evidently pleased him enough to call it 'praeclarum theorema.' $)
  prth $p |- ( ( ( ph -> ps ) /\ ( ch -> th ) ) ->
               ( ( ph /\ ch ) -> ( ps /\ th ) ) ) $=
    ( wi wa pm3.2 syl3d syl3 com23 imp4b ) ABEZCDEZACBDFZLAMCNEZBMOEABDNCBDGHIJ
    K $.
    $( [12-Aug-93] $)

  $( Theorem *3.48 of [WhiteheadRussell] p. 114. $)
  pm3.48 $p |- ( ( ( ph -> ps ) /\ ( ch -> th ) ) ->
               ( ( ph \/ ch ) -> ( ps \/ th ) ) ) $=
    ( wi wa wn wo pm3.26 con3d pm3.27 syl34d df-or 3imtr4g ) ABEZCDEZFZAGZCEBGZ
    DEACHBDHQSRCDQABOPIJOPKLACMBDMN $.
    $( [28-Jan-97] $)

  ${
    anim12d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    anim12d.2 $e |- ( ph -> ( th -> ta ) ) $.
    $( Conjoin antecedents and consequents in a deduction. $)
    anim12d $p |- ( ph -> ( ( ps /\ th ) -> ( ch /\ ta ) ) ) $=
      ( wi wa prth sylanc ) BCHDEHBDICEIHABCDEJFGK $.
      $( [3-Apr-94] $)
  $}

  ${
    anim1d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Add a conjunct to right of antecedent and consequent in a deduction. $)
    anim1d $p |- ( ph -> ( ( ps /\ th ) -> ( ch /\ th ) ) ) $=
      ( idd anim12d ) ABCDDEADFG $.
      $( [3-Apr-94] $)

    $( Add a conjunct to left of antecedent and consequent in a deduction. $)
    anim2d $p |- ( ph -> ( ( th /\ ps ) -> ( th /\ ch ) ) ) $=
      ( idd anim12d ) ADDBCADFEG $.
      $( [5-Aug-93] $)
  $}

  $( Theorem *3.45 (Fact) of [WhiteheadRussell] p. 113. $)
  pm3.45 $p |-  ( ( ph -> ps ) -> ( ( ph /\ ch ) -> ( ps /\ ch ) ) ) $=
    ( wi id anim1d ) ABDZABCGEF $.
    $( [17-Jan-05] $) $( [3-Jan-05] $)

  ${
    $v et $. $( Greek eta $)
    im2an9.wet $f wff et $.
    im2an9.1 $e |- ( ph -> ( ps -> ch ) ) $.
    im2an9.2 $e |- ( th -> ( ta -> et ) ) $.

    $( Deduction joining nested implications to form implication of
       conjunctions. $)
    im2anan9 $p |- ( ( ph /\ th ) -> ( ( ps /\ ta ) -> ( ch /\ et ) ) ) $=
      ( wa wi adantr adantl anim12d ) ADIBCEFABCJDGKDEFJAHLM $.
      $( [29-Feb-96] $)

    $( Deduction joining nested implications to form implication of
       conjunctions. $)
    im2anan9r $p |- ( ( th /\ ph ) -> ( ( ps /\ ta ) -> ( ch /\ et ) ) ) $=
      ( wa wi adantl adantr anim12d ) DAIBCEFABCJDGKDEFJAHLM $.
      $( [29-Feb-96] $)

  $}

  ${
    orim12d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    orim12d.2 $e |- ( ph -> ( th -> ta ) ) $.
    $( Disjoin antecedents and consequents in a deduction. $)
    orim12d $p |- ( ph -> ( ( ps \/ th ) -> ( ch \/ ta ) ) ) $=
      ( wi wo pm3.48 sylanc ) BCHDEHBDICEIHABCDEJFGK $.
      $( [10-May-94] $)
  $}

  ${
    orim1d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Disjoin antecedents and consequents in a deduction. $)
    orim1d $p |- ( ph -> ( ( ps \/ th ) -> ( ch \/ th ) ) ) $=
      ( idd orim12d ) ABCDDEADFG $.
      $( [23-Apr-95] $)

    $( Disjoin antecedents and consequents in a deduction. $)
    orim2d $p |- ( ph -> ( ( th \/ ps ) -> ( th \/ ch ) ) ) $=
      ( idd orim12d ) ADDBCADFEG $.
      $( [23-Apr-95] $)
  $}

  $( Theorem *2.85 of [WhiteheadRussell] p. 108. $)
  pm2.85 $p |-  ( ( ( ph \/ ps ) -> ( ph \/ ch ) ) ->
                ( ph \/ ( ps -> ch ) ) ) $=
    ( wo wi wn imor pm2.48 orim1i sylbi orbi2i orordi bitr2 sylib ) ABDZACDZEZA
    BFZDZPDZABCEZDZQOFZPDTOPGUCSPABHIJUBARCDZDTUAUDABCGKARCLMN $.
    $( [9-Jan-05] $) $( [3-Jan-05] $)

  ${
    pm3.2ni.1 $e |- -. ph $.
    pm3.2ni.2 $e |- -. ps $.
    $( Infer negated disjunction of negated premises. $)
    pm3.2ni $p |- -. ( ph \/ ps ) $=
      ( wo wn wa pm3.2i ioran mpbir ) ABEFAFZBFZGKLCDHABIJ $.
      $( [4-Apr-95] $)
  $}

  $( Elimination of redundant internal disjunct.  Compare Theorem *4.45
     of [WhiteheadRussell] p. 119. $)
  oel $p |- ( ph <-> ( ( ph \/ ps ) /\ ph ) ) $=
    ( wo wa orc ancri pm3.27 impbi ) AABCZADAIABEFIAGH $.
    $( [5-Aug-93] $)

  $( Distribution of implication over biconditional.  Theorem *5.74 of
     [WhiteheadRussell] p. 126. $)
  pm5.74 $p |- ( ( ph -> ( ps <-> ch ) ) <->
               ( ( ph -> ps ) <-> ( ph -> ch ) ) ) $=
    ( wb wi bi1 syl3 a2d bi2 impbid wa pm2.86d anim12d pm4.24 bi 3imtr4g impbi
    ) ABCDZEZABEZACEZDZSTUASABCRBCEZABCFGHSACBRCBEZABCIGHJUBAAKUCUDKARUBAUCAUDU
    BABCTUAFLUBACBTUAILMANBCOPQ $.
    $( [1-Aug-94] $)

  ${
    pm5.74i.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    $( Distribution of implication over biconditional (inference rule). $)
    pm5.74i $p |- ( ( ph -> ps ) <-> ( ph -> ch ) ) $=
      ( wb wi pm5.74 mpbi ) ABCEFABFACFEDABCGH $.
      $( [1-Aug-94] $)
  $}

  ${
    pm5.74d.1 $e |- ( ph -> ( ps -> ( ch <-> th ) ) ) $.
    $( Distribution of implication over biconditional (deduction rule). $)
    pm5.74d $p |- ( ph -> ( ( ps -> ch ) <-> ( ps -> th ) ) ) $=
      ( wb wi pm5.74 sylib ) ABCDFGBCGBDGFEBCDHI $.
      $( [21-Mar-96] $)
  $}

  ${
    pm5.74ri.1 $e |- ( ( ph -> ps ) <-> ( ph -> ch ) ) $.
    $( Distribution of implication over biconditional (reverse inference
       rule). $)
    pm5.74ri $p |- ( ph -> ( ps <-> ch ) ) $=
      ( wb wi pm5.74 mpbir ) ABCEFABFACFEDABCGH $.
      $( [1-Aug-94] $)
  $}

  ${
    pm5.74rd.1 $e |- ( ph -> ( ( ps -> ch ) <-> ( ps -> th ) ) ) $.
    $( Distribution of implication over biconditional (deduction rule). $)
    pm5.74rd $p |- ( ph -> ( ps -> ( ch <-> th ) ) ) $=
      ( wi wb pm5.74 sylibr ) ABCFBDFGBCDGFEBCDHI $.
      $( [19-Mar-97] $)
  $}

  ${
    mpbidi.min $e |- ( th -> ( ph -> ps ) ) $.
    mpbidi.maj $e |- ( ph -> ( ps <-> ch ) ) $.
    $( A deduction from a biconditional, related to modus ponens. $)
    mpbidi $p |- ( th -> ( ph -> ch ) ) $=
      ( wi pm5.74i sylib ) DABGACGEABCFHI $.
      $( [9-Aug-94] $)
  $}

  $( Implication in terms of implication and biconditional. $)
  ibib $p |- ( ( ph -> ps ) <-> ( ph -> ( ph <-> ps ) ) ) $=
    ( wb wa pm3.4 pm3.26 a1d impbid exp bi1 com12 pm5.74i ) ABABCZABMABMABDZABA
    BENABABFGHIMABABJKHL $.
    $( [31-Mar-94] $)

  ${
    ibi.1 $e |- ( ph -> ( ph <-> ps ) ) $.
    $( Inference that converts a biconditional implied by one of its arguments,
       into an implication. $)
    ibi $p |- ( ph -> ps ) $=
      ( biimpd pm2.43i ) ABAABCDE $.
      $( [17-Oct-03] $) $( [17-Oct-03] $)
  $}

  ${
    ibir.1 $e |- ( ph -> ( ps <-> ph ) ) $.
    $( Inference that converts a biconditional implied by one of its arguments,
       into an implication. $)
    ibir $p |- ( ph -> ps ) $=
      ( bicomd ibi ) ABABACDE $.
      $( [28-Jul-04] $) $( [22-Jul-04] $)
  $}

  ${
    ibd.1 $e |- ( ph -> ( ps -> ( ps <-> ch ) ) ) $.
    $( Deduction that converts a biconditional implied by one of its arguments,
       into an implication. $)
    ibd $p |- ( ph -> ( ps -> ch ) ) $=
      ( wb wi ibib sylibr ) ABBCEFBCFDBCGH $.
      $( [27-Jun-04] $) $( [26-Jun-04] $)
  $}

  $( Theorem *5.501 of [WhiteheadRussell] p. 125. $)
  pm5.501 $p |-  ( ph -> ( ps <-> ( ph <-> ps ) ) ) $=
    ( wb ibib pm5.74ri ) ABABCABDE $.
    $( [1-Feb-05] $) $( [3-Jan-05] $)

  $( Distributive law for disjunction.  Theorem *4.41 of [WhiteheadRussell]
     p. 119. $)
  ordi $p |- ( ( ph \/ ( ps /\ ch ) ) <-> ( ( ph \/ ps ) /\ ( ph \/ ch ) ) ) $=
    ( wa wo pm3.26 orim2i pm3.27 jca wn wi df-or pm3.43i 3imtr4g sylbi imp
    impbi ) ABCDZEZABEZACEZDSTUARBABCFGRCABCHGITUASTAJZBKZUASKABLUCUBCKUBRKUASU
    BBCMACLARLNOPQ $.
    $( [5-Aug-93] $)

  $( Distributive law for disjunction. $)
  ordir $p |- ( ( ( ph /\ ps ) \/ ch ) <->
              ( ( ph \/ ch ) /\ ( ps \/ ch ) ) ) $=
    ( wa wo ordi orcom anbi12i 3bitr4 ) CABDZECAEZCBEZDJCEACEZBCEZDCABFJCGMKNLA
    CGBCGHI $.
    $( [12-Aug-94] $)

  $( Distributive law for implication over conjunction.  Compare Theorem
     *4.76 of [WhiteheadRussell] p. 121. $)
  jcab $p |- ( ( ph -> ( ps /\ ch ) ) <->
                 ( ( ph -> ps ) /\ ( ph -> ch ) ) ) $=
    ( wn wa wo wi ordi imor anbi12i 3bitr4 ) ADZBCEZFLBFZLCFZEAMGABGZACGZELBCHA
    MIPNQOABIACIJK $.
    $( [3-Apr-94] $)


  ${
    jcad.1 $e |- ( ph -> ( ps -> ch ) ) $.
    jcad.2 $e |- ( ph -> ( ps -> th ) ) $.
    $( Deduction conjoining the consequents of two implications. $)
    jcad $p |- ( ph -> ( ps -> ( ch /\ th ) ) ) $=
      ( wa imp jca exp ) ABCDGABGCDABCEHABDFHIJ $.
      $( [5-Aug-93] $)
  $}

  $( Distributive law for conjunction.  Theorem *4.4 of [WhiteheadRussell]
     p. 118. $)
  andi $p |- ( ( ph /\ ( ps \/ ch ) ) <-> ( ( ph /\ ps ) \/ ( ph /\ ch ) ) ) $=
    ( wn wo wa ordi ioran orbi2i ianor anbi12i 3bitr4 negbii anor oran ) ADZBCE
    ZDZEZDABFZDZACFZDZFZDAQFTUBESUDPBDZCDZFZEPUEEZPUFEZFSUDPUEUFGRUGPBCHIUAUHUC
    UIABJACJKLMAQNTUBOL $.
    $( [5-Aug-93] $)

  $( Distributive law for conjunction. $)
  andir $p |- ( ( ( ph \/ ps ) /\ ch ) <->
              ( ( ph /\ ch ) \/ ( ps /\ ch ) ) ) $=
    ( wo wa andi ancom orbi12i 3bitr4 ) CABDZECAEZCBEZDJCEACEZBCEZDCABFJCGMKNLA
    CGBCGHI $.
    $( [12-Aug-94] $)

  $( Double distributive law for disjunction. $)
  orddi $p |- ( ( ( ph /\ ps ) \/ ( ch /\ th ) ) <->
              ( ( ( ph \/ ch ) /\ ( ph \/ th ) ) /\
              ( ( ps \/ ch ) /\ ( ps \/ th ) ) ) ) $=
    ( wa wo ordir ordi anbi12i bitr ) ABECDEZFAKFZBKFZEACFADFEZBCFBDFEZEABKGLNM
    OACDHBCDHIJ $.
    $( [12-Aug-94] $)

  $( Double distributive law for conjunction. $)
  anddi $p |- ( ( ( ph \/ ps ) /\ ( ch \/ th ) ) <->
              ( ( ( ph /\ ch ) \/ ( ph /\ th ) ) \/
              ( ( ps /\ ch ) \/ ( ps /\ th ) ) ) ) $=
    ( wo wa andir andi orbi12i bitr ) ABECDEZFAKFZBKFZEACFADFEZBCFBDFEZEABKGLNM
    OACDHBCDHIJ $.
    $( [12-Aug-94] $)

  $( Prove formula-building rules for the biconditional connective. $)

  ${
    bibi.a $e |- ( ph <-> ps ) $.

    $( Inference adding a biconditional to the left in an equivalence. $)
    bibi2i $p |- ( ( ch <-> ph ) <-> ( ch <-> ps ) ) $=
      ( wb wi wa bi imbi1i anbi2i imbi2i anbi1i bitr4 3bitr ) CAECAFZACFZGOBCFZ
      GZCBEZCAHPQOABCDIJRCBFZQGSOTQABCDKLCBHMN $.
      $( [5-Aug-93] $)

    $( Inference adding a biconditional to the right in an equivalence. $)
    bibi1i $p |- ( ( ph <-> ch ) <-> ( ps <-> ch ) ) $=
      ( wb bicom bibi2i 3bitr ) ACECAECBEBCEACFABCDGCBFH $.
      $( [5-Aug-93] $)

  $}

  ${
    bibi12.1 $e |- ( ph <-> ps ) $.
    bibi12.2 $e |- ( ch <-> th ) $.
    $( The equivalence of two equivalences. $)
    bibi12i $p |- ( ( ph <-> ch ) <-> ( ps <-> th ) ) $=
      ( wb bibi2i bibi1i bitr ) ACGADGBDGCDAFHABDEIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    bid.1 $e |- ( ph -> ( ps <-> ch ) ) $.

    $( Deduction negating both sides of a logical equivalence. $)
    negbid $p |- ( ph -> ( -. ps <-> -. ch ) ) $=
      ( wb wn pm4.11 sylib ) ABCEBFCFEDBCGH $.
      $( [21-May-94] $)

    $( Deduction adding an antecedent to both sides of a logical
       equivalence. $)
    imbi2d $p |- ( ph -> ( ( th -> ps ) <-> ( th -> ch ) ) ) $=
      ( wb a1d pm5.74d ) ADBCABCFDEGH $.
      $( [5-Aug-93] $)

    $( Deduction adding a consequent to both sides of a logical equivalence. $)
    imbi1d $p |- ( ph -> ( ( ps -> th ) <-> ( ch -> th ) ) ) $=
      ( wn wi negbid imbi2d pm4.1 3bitr4g ) ADFZBFZGLCFZGBDGCDGAMNLABCEHIBDJCDJ
      K $.
      $( [5-Aug-93] $)

    $( Deduction adding a left disjunct to both sides of a logical
       equivalence. $)
    orbi2d $p |- ( ph -> ( ( th \/ ps ) <-> ( th \/ ch ) ) ) $=
      ( wn wi wo imbi2d df-or 3bitr4g ) ADFZBGLCGDBHDCHABCLEIDBJDCJK $.
      $( [5-Aug-93] $)

    $( Deduction adding a right disjunct to both sides of a logical
       equivalence. $)
    orbi1d $p |- ( ph -> ( ( ps \/ th ) <-> ( ch \/ th ) ) ) $=
      ( wo orbi2d orcom 3bitr4g ) ADBFDCFBDFCDFABCDEGBDHCDHI $.
      $( [5-Aug-93] $)

    $( Deduction adding a left conjunct to both sides of a logical
       equivalence. $)
    anbi2d $p |- ( ph -> ( ( th /\ ps ) <-> ( th /\ ch ) ) ) $=
      ( wa biimpd anim2d biimprd impbid ) ADBFDCFABCDABCEGHACBDABCEIHJ $.
      $( [5-Aug-93] $)

    $( Deduction adding a right conjunct to both sides of a logical
       equivalence. $)
    anbi1d $p |- ( ph -> ( ( ps /\ th ) <-> ( ch /\ th ) ) ) $=
      ( wa anbi2d ancom 3bitr4g ) ADBFDCFBDFCDFABCDEGBDHCDHI $.
      $( [5-Aug-93] $)

    $( Deduction adding a biconditional to the left in an equivalence. $)
    bibi2d $p |- ( ph -> ( ( th <-> ps ) <-> ( th <-> ch ) ) ) $=
      ( wi wa wb imbi2d anbi1d imbi1d anbi2d bitrd bi 3bitr4g ) ADBFZBDFZGZDCFZ
      CDFZGZDBHDCHARSQGUAAPSQABCDEIJAQTSABCDEKLMDBNDCNO $.
      $( [5-Aug-93] $)

    $( Deduction adding a biconditional to the right in an equivalence. $)
    bibi1d $p |- ( ph -> ( ( ps <-> th ) <-> ( ch <-> th ) ) ) $=
      ( wb bibi2d bicom 3bitr4g ) ADBFDCFBDFCDFABCDEGBDHCDHI $.
      $( [5-Aug-93] $)

  $}

  $( Theorem *4.84 of [WhiteheadRussell] p. 122. $)
  imbi1 $p |-  ( ( ph <-> ps ) -> ( ( ph -> ch ) <-> ( ps -> ch ) ) ) $=
    ( wb id imbi1d ) ABDZABCGEF $.
    $( [9-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *4.85 of [WhiteheadRussell] p. 122. $)
  imbi2 $p |-  ( ( ph <-> ps ) -> ( ( ch -> ph ) <-> ( ch -> ps ) ) ) $=
    ( wb ax-1 pm5.74d ) ABDZCABGCEF $.
    $( [9-Jan-05] $)


  ${
    bi12d.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    bi12d.2 $e |- ( ph -> ( th <-> ta ) ) $.

    $( Deduction joining two equivalences to form equivalence of
       implications. $)
    imbi12d $p |- ( ph -> ( ( ps -> th ) <-> ( ch -> ta ) ) ) $=
      ( wi imbi1d imbi2d bitrd ) ABDHCDHCEHABCDFIADECGJK $.
      $( [5-Aug-93] $)

    $( Deduction joining two equivalences to form equivalence of
       disjunctions. $)
    orbi12d $p |- ( ph -> ( ( ps \/ th ) <-> ( ch \/ ta ) ) ) $=
      ( wo orbi1d orbi2d bitrd ) ABDHCDHCEHABCDFIADECGJK $.
      $( [5-Aug-93] $)

    $( Deduction joining two equivalences to form equivalence of
       conjunctions. $)
    anbi12d $p |- ( ph -> ( ( ps /\ th ) <-> ( ch /\ ta ) ) ) $=
      ( wa anbi1d anbi2d bitrd ) ABDHCDHCEHABCDFIADECGJK $.
      $( [5-Aug-93] $)

    $( Deduction joining two equivalences to form equivalence of
       biconditionals. $)
    bibi12d $p |- ( ph -> ( ( ps <-> th ) <-> ( ch <-> ta ) ) ) $=
      ( wb bibi1d bibi2d bitrd ) ABDHCDHCEHABCDFIADECGJK $.
      $( [5-Aug-93] $)

  $}

  ${
    $v et $. $( Greek eta $)
    bi2an9.wet $f wff et $.
    bi2an9.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    bi2an9.2 $e |- ( th -> ( ta <-> et ) ) $.

    $( Deduction joining two equivalences to form equivalence of
       conjunctions. $)
    bi2anan9 $p |- ( ( ph /\ th ) -> ( ( ps /\ ta ) <-> ( ch /\ et ) ) ) $=
      ( wa anbi1d anbi2d sylan9bb ) ABEICEIDCFIABCEGJDEFCHKL $.
      $( [31-Jul-95] $)

    $( Deduction joining two equivalences to form equivalence of
       conjunctions. $)
    bi2anan9r $p |- ( ( th /\ ph ) -> ( ( ps /\ ta ) <-> ( ch /\ et ) ) ) $=
      ( wa wb bi2anan9 ancoms ) ADBEICFIJABCDEFGHKL $.
      $( [19-Feb-96] $)

    $( Deduction joining two biconditionals with different antecedents. $)
    bi2bian9 $p |- ( ( ph /\ th ) -> ( ( ps <-> ta ) <-> ( ch <-> et ) ) ) $=
      ( wa wb adantr adantl bibi12d ) ADIBCEFABCJDGKDEFJAHLM $.
      $( [14-May-04] $) $( [12-May-04] $)
  $}

  $( Implication in terms of biconditional and conjunction.  Theorem *4.71 of
     [WhiteheadRussell] p. 120. $)
  pm4.71 $p |- ( ( ph -> ps ) <-> ( ph <-> ( ph /\ ps ) ) ) $=
    ( wi wa wb ancl pm3.26 a1i impbid bi1 pm3.27 syl6 impbi ) ABCZAABDZEZNAOABF
    OACNABGHIPAOBAOJABKLM $.
    $( [5-Aug-93] $)

  $( Implication in terms of biconditional and conjunction.  Theorem *4.71 of
     [WhiteheadRussell] p. 120 (with conjunct reversed). $)
  pm4.71r $p |- ( ( ph -> ps ) <-> ( ph <-> ( ps /\ ph ) ) ) $=
    ( wi wa wb pm4.71 ancom bibi2i bitr ) ABCAABDZEABADZEABFJKAABGHI $.
    $( [25-Jul-99] $)

  ${
    pm4.71i.1 $e |- ( ph -> ps ) $.
    $( Inference converting an implication to a biconditional with conjunction.
       Inference from Theorem *4.71 of [WhiteheadRussell] p. 120. $)
    pm4.71i $p |- ( ph <-> ( ph /\ ps ) ) $=
      ( wi wa wb pm4.71 mpbi ) ABDAABEFCABGH $.
      $( [6-Jan-04] $) $( [4-Jan-04] $)
  $}

  ${
    pm4.71ri.1 $e |- ( ph -> ps ) $.
    $( Inference converting an implication to a biconditional with conjunction.
       Inference from Theorem *4.71 of [WhiteheadRussell] p. 120 (with
       conjunct reversed). $)
    pm4.71ri $p |- ( ph <-> ( ps /\ ph ) ) $=
      ( wi wa wb pm4.71r mpbi ) ABDABAEFCABGH $.
      $( [1-Dec-03] $) $( [1-Dec-03] $)
  $}

  ${
    pm4.71rd.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction converting an implication to a biconditional with conjunction.
       Deduction from Theorem *4.71 of [WhiteheadRussell] p. 120. $)
    pm4.71rd $p |- ( ph -> ( ps <-> ( ch /\ ps ) ) ) $=
      ( wi wa wb pm4.71r sylib ) ABCEBCBFGDBCHI $.
      $( [12-Feb-05] $) $( [10-Feb-05] $)
  $}

  $( Implication in terms of biconditional and disjunction.  Theorem *4.72 of
     [WhiteheadRussell] p. 121. $)
  pm4.72 $p |- ( ( ph -> ps ) <-> ( ps <-> ( ph \/ ps ) ) ) $=
    ( wi wo wb olc a1i pm2.621 impbid bi2 pm2.67 syl impbi ) ABCZBABDZEZNBOBOCN
    BAFGABHIPOBCNBOJABKLM $.
    $( [30-Aug-93] $)

  $( Introduction of antecedent as conjunct. Theorem *4.73 of
     [WhiteheadRussell] p. 121. $)
  iba $p |- ( ph -> ( ps <-> ( ps /\ ph ) ) ) $=
    ( wa ancrb pm5.74ri ) ABBACABDE $.
    $( [30-Mar-94] $)

  $( Introduction of antecedent as conjunct. $)
  ibar $p |- ( ph -> ( ps <-> ( ph /\ ps ) ) ) $=
    ( wa anclb pm5.74ri ) ABABCABDE $.
    $( [5-Dec-95] $)

  $( Distribution of implication over biconditional.  Theorem *5.32 of
     [WhiteheadRussell] p. 125. $)
  pm5.32 $p |- ( ( ph -> ( ps <-> ch ) ) <->
               ( ( ph /\ ps ) <-> ( ph /\ ch ) ) ) $=
    ( wb wi wn wa pm4.11 imbi2i pm5.74 3bitr df-an bibi12i bitr4 ) ABCDZEZABFZE
    ZFZACFZEZFZDZABGZACGZDPAQTDZERUADUCOUFABCHIAQTJRUAHKUDSUEUBABLACLMN $.
    $( [1-Aug-94] $)

  ${
    pm5.32i.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    $( Distribution of implication over biconditional (inference rule). $)
    pm5.32i $p |- ( ( ph /\ ps ) <-> ( ph /\ ch ) ) $=
      ( wb wi wa pm5.32 mpbi ) ABCEFABGACGEDABCHI $.
      $( [1-Aug-94] $)

    $( Distribution of implication over biconditional (inference rule). $)
    pm5.32ri $p |- ( ( ps /\ ph ) <-> ( ch /\ ph ) ) $=
      ( wa pm5.32i ancom 3bitr4 ) ABEACEBAECAEABCDFBAGCAGH $.
      $( [12-Mar-95] $)
  $}

  ${
    pm5.32d.1 $e |- ( ph -> ( ps -> ( ch <-> th ) ) ) $.
    $( Distribution of implication over biconditional (deduction rule). $)
    pm5.32d $p |- ( ph -> ( ( ps /\ ch ) <-> ( ps /\ th ) ) ) $=
      ( wb wi wa pm5.32 sylib ) ABCDFGBCHBDHFEBCDIJ $.
      $( [29-Oct-96] $)

    $( Distribution of implication over biconditional (deduction rule). $)
    pm5.32rd $p |- ( ph -> ( ( ch /\ ps ) <-> ( th /\ ps ) ) ) $=
      ( wa pm5.32d ancom 3bitr4g ) ABCFBDFCBFDBFABCDEGCBHDBHI $.
      $( [1-Jan-05] $) $( [25-Dec-04] $)
  $}

  $( Absorption of disjunction into equivalence. $)
  oibabs $p |- ( ( ph <-> ps ) <-> ( ( ph \/ ps ) -> ( ph <-> ps ) ) ) $=
    ( wb wo wi ax-1 orc syl4 ibd olc ibib bicom imbi2i bitr sylibr impbid
    impbi ) ABCZABDZREZRSFTABTABASRABGHITBREZBAEZBSRBAJHUBBBACZEUABAKUCRBBALMNO
    PQ $.
    $( [6-Aug-95] $)

  $( Law of excluded middle.  Theorem *2.11 of [WhiteheadRussell] p. 101.  It
     says that something is either true or not true; there are no in-between
     values of truth.  This is an essential distinction of our classical logic
     and is not a theorem of intuitionistic logic. $)
  exmid $p |- ( ph \/ -. ph ) $=
    ( wn id orri ) AABZECD $.
    $( [5-Aug-93] $)

  $( Theorem *2.1 of [WhiteheadRussell] p. 101. $)
  pm2.1 $p |-  ( -. ph \/ ph ) $=
    ( wn nega orri ) ABAACD $.
    $( [7-Jan-05] $)


  $( Law of contradiction.  Theorem *3.24 of [WhiteheadRussell] p. 111. $)
  pm3.24 $p |- -. ( ph /\ -. ph ) $=
    ( wn wa wo exmid ianor mpbir ) AABZCBHHBDHEAHFG $.
    $( [16-Sep-93] $)


  $( Theorem *5.18 of [WhiteheadRussell] p. 124.  This theorem says that
     logical equivalence is the same as negated "exclusive-or". $)
  pm5.18 $p |- ( ( ph <-> ps ) <-> -. ( ph <-> -. ps ) ) $=
    ( wb wn bicom wi wa pm2.61 pm2.65 con2 syl5 anim12d bi syl5ib annim syl6ib
    com12 imnan sylib negbii sylibr wo pm2.5 pm2.21 adantl sylbir jca ax-1
    adantr pm2.51 jaoi ianor 3imtr4 sylbi impbi bitr bicon2i ) ABCBACZABDZCZDAB
    EUTURUTUSACZURDZAUSEVAVBVABAFZABFZGZDZVBVAVCVDDZFVFVCVAVGVCVAAUSGZVGVCUSAFZ
    AUSFZGZVHVAVCVIAVJUSBAHVCBADZFUSVJBAIABJKLUSAMZNABOZPQVCVDRSURVEBAMTZUAVBVF
    VAVOVCDZVGUBVKVFVAVPVKVGVPVIVJBAUCVPBVLGVJBAOVLVJBAUSUDUEUFUGVGVIVJVGVHVIVN
    AVIUSAUSUHUIUFABUJUGUKVCVDULVMUMUNUOUPUQUP $.
    $( [28-Jun-02] $)

  $( Move negation outside of biconditional.  Compare Theorem *5.18 of
     [WhiteheadRussell] p. 124. $)
  nbbn $p |- ( ( -. ph <-> ps ) <-> -. ( ph <-> ps ) ) $=
    ( wn wb bicom pm5.18 bitr bicon2i ) ACZBDBIDZABDZCIBEKJKBADJCABEBAFGHG $.
    $( [27-Jun-02] $)


  $( Theorem *5.15 of [WhiteheadRussell] p. 124. $)
  pm5.15 $p |-  ( ( ph <-> ps ) \/ ( ph <-> -. ps ) ) $=
    ( wb wn pm5.18 biimpr con1i orri ) ABCZABDCZJIIJDABEFGH $.
    $( [1-Feb-05] $)


  $( Theorem *5.17 of [WhiteheadRussell] p. 124. $)
  pm5.17 $p |-  ( ( ( ph \/ ps ) /\ -. ( ph /\ ps ) ) <-> ( ph <-> -. ps ) ) $=
    ( wo wa wn wb wi orcom df-or bitr imnan bicomi anbi12i bi bitr4 bicom ) ABC
    ZABDEZDZBEZAFZATFSTAGZATGZDUAQUBRUCQBACUBABHBAIJUCRABKLMTANOTAPJ $.
    $( [22-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem *5.19 of [WhiteheadRussell] p. 124. $)
  pm5.19 $p |-  -. ( ph <-> -. ph ) $=
    ( wb wn pm4.2 pm5.18 mpbi ) AABAACBCADAAEF $.
    $( [1-Feb-05] $) $( [3-Jan-05] $)

  $( An alternate definition of the biconditional. Theorem *5.23 of
     [WhiteheadRussell] p. 124. $)
  dfbi $p |- ( ( ph <-> ps ) <-> ( ( ph /\ ps ) \/ ( -. ph /\ -. ps ) ) ) $=
    ( wb wn wa wo pm5.18 wi imnan bi2.15 iman bitr anbi12i bi ioran 3bitr4r
    bicon1i ) ABCABDZCZDABEZADZREZFZABGUCSARHZRAHZETDZUBDZESUCDUDUFUEUGABIUEUAB
    HUGBAJUABKLMARNTUBOPQL $.
    $( [27-Jun-02] $)

  $( Two ways to express "exclusive or".  Theorem *5.22 of [WhiteheadRussell]
     p. 124. $)
  xor $p |-  ( -. ( ph <-> ps ) <->
                ( ( ph /\ -. ps ) \/ ( ps /\ -. ph ) ) ) $=
    ( wn wb wa wo dfbi nbbn ancom pm4.13 anbi1i orbi12i orcom bitr3 3bitr3 ) AC
    ZBDPBEZPCZBCZEZFZABDCASEZBPEZFZPBGABHUAUCUBFUDUCQUBTBPIARSAJKLUCUBMNO $.
    $( [11-Jan-05] $) $( [3-Jan-05] $)

  $( Theorem *5.24 of [WhiteheadRussell] p. 124. $)
  pm5.24 $p |-  ( -. ( ( ph /\ ps ) \/ ( -. ph /\ -. ps ) ) <->
                ( ( ph /\ -. ps ) \/ ( ps /\ -. ph ) ) ) $=
    ( wa wn wo wb dfbi negbii xor bitr3 ) ABCADZBDZCEZDABFZDALCBKCENMABGHABIJ
    $.
    $( [11-Feb-05] $) $( [3-Jan-05] $)

  $( Two ways to express "exclusive or". $)
  xor2 $p |-  ( -. ( ph <-> ps ) <-> ( ( ph \/ ps ) /\ -. ( ph /\ ps ) ) ) $=
    ( wb wn wa wo xor ioran pm5.24 oran anbi2i ancom bitr3 3bitr3 bitr ) ABCDAB
    DZEBADZEFZABFZABEZDZEZABGTQPEZFDUAUCDZEZRUBTUCHABIUEUASEUBSUDUAABJKUASLMNO
    $.
    $( [11-Feb-05] $)



$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Miscellaneous theorems of propositional calculus
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( Two propositions are equivalent if they are both true.  Theorem *5.1 of
     [WhiteheadRussell] p. 123. $)
  pm5.1 $p |- ( ( ph /\ ps ) -> ( ph <-> ps ) ) $=
    ( wb pm5.501 biimpa ) ABABCABDE $.
    $( [21-May-94] $)

  $( Two propositions are equivalent if they are both false.  Theorem *5.21 of
     [WhiteheadRussell] p. 124. $)
  pm5.21 $p |- ( ( -. ph /\ -. ps ) -> ( ph <-> ps ) ) $=
    ( wn wa pm5.1 bicon4d ) ACZBCZDABGHEF $.
    $( [21-May-94] $)


  ${
    pm5.21ni.1 $e |- ( ph -> ps ) $.
    pm5.21ni.2 $e |- ( ch -> ps ) $.
    $( Two propositions implying a false one are equivalent. $)
    pm5.21ni $p |- ( -. ps -> ( ph <-> ch ) ) $=
      ( wn wb pm5.21 con3i sylanc ) AFCFACGBFACHABDICBEIJ $.
      $( [16-Feb-96] $)
  $}


  ${
    pm5.21nii.1 $e |- ( ph -> ps ) $.
    pm5.21nii.2 $e |- ( ch -> ps ) $.
    pm5.21nii.3 $e |- ( ps -> ( ph <-> ch ) ) $.
    $( Elimination of antecedent implied by each side of biconditional. $)
    pm5.21nii $p |- ( ph <-> ch ) $=
      ( wb pm5.21ni pm2.61i ) BACGFABCDEHI $.
      $( [21-May-99] $)
  $}

  $( Elimination of antecedents in an implication. $)
  elimant $p |- ( ( ( ph -> ps ) /\ ( ( ps -> ch ) -> ( ph -> th ) ) ) ->
                ( ph -> ( ch -> th ) ) ) $=
    ( wi wa wb id impac pm5.1 syl imbi1d biimpd exp com23 imp imdi syl6ibr
    pm2.43d ) ABEZBCEZADEZEZFZACDEZUDAACEZUBEZAUEETUCAUGETAUCUGTAUCUGETAFZUCUGU
    HUAUFUBUHBACUHBAFBAGTABTHIBAJKLLMNOPACDQRS $.
    $( [13-Oct-99] $)

  ${
    baib.1 $e |- ( ph <-> ( ps /\ ch ) ) $.
    $( Move conjunction outside of biconditional. $)
    baib $p |- ( ps -> ( ph <-> ch ) ) $=
      ( wa ibar syl6rbbr ) BCBCEABCFDG $.
      $( [13-May-99] $)
  $}

  ${
    baibr.1 $e |- ( ph <-> ( ps /\ ch ) ) $.
    $( Move conjunction outside of biconditional. $)
    baibr $p |- ( ps -> ( ch <-> ph ) ) $=
      ( baib bicomd ) BACABCDEF $.
      $( [11-Jul-94] $)
  $}

  ${
    msca.1 $e |- ( ph -> ( ps -> ch ) ) $.
    msca.2 $e |- ( th -> ( ps -> -. ch ) ) $.
    $( Syllogism combined with contraposition. $)
    msca $p |- ( ph -> ( ps -> -. th ) ) $=
      ( wn wa wi pm3.27 imp jc nsyl exp ) ABDGABHZBCGIDOBCABJABCEKLFMN $.
      $( [5-Aug-93] $)
  $}

  $( Disjunction in consequent versus conjunction in antecedent.  Similar to
     Theorem *5.6 of [WhiteheadRussell] p. 125. $)
  orcana $p |- ( ( ph -> ( ps \/ ch ) ) <-> ( ( ph /\ -. ps ) -> ch ) ) $=
    ( wo wi wn wa df-or imbi2i impexp bitr4 ) ABCDZEABFZCEZEAMGCELNABCHIAMCJK
    $.
    $( [8-Jun-94] $)

  $( Theorem *5.6 of [WhiteheadRussell] p. 125. $)
  pm5.6 $p |-  ( ( ( ph /\ -. ps ) -> ch ) <-> ( ph -> ( ps \/ ch ) ) ) $=
    ( wo wi wn wa orcana bicomi ) ABCDEABFGCEABCHI $.
    $( [22-Mar-05] $) $( [3-Jan-05] $)

  $( Disjunction distributes over the biconditional.  An axiom of system DS in
     Vladimir Lifschitz, "On calculational proofs" (1998),
     ~ http://citeseer.lcs.mit.edu/lifschitz98calculational.html . $)
  orbidi $p |-  ( ( ph \/ ( ps <-> ch ) ) <->
                ( ( ph \/ ps ) <-> ( ph \/ ch ) ) ) $=
    ( wb wo orc a1d impbid id orbi2d jaoi wi wa pm2.85 anim12i bi orbi2i ordi
    bitr 3imtr4 impbi ) ABCDZEZABEZACEZDZAUFUBAUDUEAUEUDACFGAUDUEABFGHUBBCAUBIJ
    KUDUELZUEUDLZMABCLZEZACBLZEZMZUFUCUGUJUHULABCNACBNOUDUEPUCAUIUKMZEUMUBUNABC
    PQAUIUKRSTUA $.
    $( [9-Jan-05] $) $( [8-Jan-05] $)

  $( Associative law for the biconditional.  An axiom of system DS in Vladimir
     Lifschitz, "On calculational proofs" (1998),
     ~ http://citeseer.lcs.mit.edu/lifschitz98calculational.html .  Noted
     by Jan Lukasiewicz c. 1923. $)
  biass $p |- ( ( ( ph <-> ps ) <-> ch ) <-> ( ph <-> ( ps <-> ch ) ) ) $=
    ( wb wa wn wo andi dfbi anbi2i anass orbi12i 3bitr4 xor ancom orbi2i bitr
    anbi1i andir or42 3bitr 3bitr4r ) ABCDZEZAFZUCFZEZGABEZCEZABFZEZCFZEZGZUEBE
    ZULEZUEUJEZCEZGZGZAUCDABDZCDZUDUNUGUSABCEZUJULEZGZEAVCEZAVDEZGUDUNAVCVDHUCV
    EABCIJUIVFUMVGABCKAUJULKLMUEBULEZUJCEZGZEUEVHEZUEVIEZGUGUSUEVHVIHUFVJUEUFVH
    CUJEZGVJBCNVMVIVHCUJOPQJUPVKURVLUEBULKUEUJCKLMLAUCIVBVACEZVAFZULEZGUIURGZUM
    UPGZGUTVACIVNVQVPVRVNUHUQGZCEVQVAVSCABIRUHUQCSQVPUKUOGZULEVRVOVTULVOUKBUEEZ
    GVTABNWAUOUKBUEOPQRUKUOULSQLUIURUMUPTUAUB $.
    $( [11-Jan-05] $) $( [8-Jan-05] $)

  $( Lukasiewicz's shortest axiom for equivalential calculus.  Storrs McCall,
     ed., _Polish Logic 1920-1939_ (Oxford, 1967), p. 96. $)
  biluk $p |- ( ( ph <-> ps ) <-> ( ( ch <-> ps ) <-> ( ph <-> ch ) ) ) $=
    ( wb bicom bibi1i biass bitr mpbi bitr4 ) ABDZCBACDZDZDZCBDLDKCDZMDKNDOBADZ
    CDMKPCABEFBACGHKCMGICBLGJ $.
    $( [11-Jan-05] $)


  $( Dijkstra-Scholten's Golden Rule for calculational proofs. $)
  bigolden $p |- ( ( ( ph /\ ps ) <-> ph ) <-> ( ps <-> ( ph \/ ps ) ) ) $=
    ( wi wa wb wo pm4.71 pm4.72 bicom 3bitr3r ) ABCAABDZEBABFEKAEABGABHAKIJ $.
    $( [12-Jan-05] $)


  $( Theorem *5.75 of [WhiteheadRussell] p. 126. $)
  pm5.75 $p |-  ( ( ( ch -> -. ps ) /\ ( ph <-> ( ps \/ ch ) ) ) ->
                ( ( ph /\ -. ps ) <-> ch ) ) $=
    ( wn wi wo wb wa bi1 pm5.6 sylibr adantl bi2 olc syl34 syl exp3a a2d com12
    imp pm3.26 jcad impbid ) CBDZEZABCFZGZHZAUDHZCUGUICEZUEUGAUFEUJAUFIABCJKLUH
    CAUDUEUGCAEZUGUEUKUGCUDAUGCUDAUGCBAFZEZCUDHAEUGUFAEUMAUFMCUFAULCBNABNOPCBAJ
    KQRSTUEUGUAUBUC $.
    $( [22-Mar-05] $) $( [3-Jan-05] $)

  $( Theorem to move a conjunct in and out of a negation. $)
  nan $p |- ( ( ph -> -. ( ps /\ ch ) ) <-> ( ( ph /\ ps ) -> -. ch ) ) $=
    ( wa wn wi impexp imnan imbi2i bitr2 ) ABDCEZFABKFZFABCDEZFABKGLMABCHIJ $.
    $( [9-Nov-03] $) $( [9-Nov-03] $)

  ${
    orcanai.1 $e |- ( ph -> ( ps \/ ch ) ) $.
    $( Change disjunction in consequent to conjunction in antecedent. $)
    orcanai $p |- ( ( ph /\ -. ps ) -> ch ) $=
      ( wn ord imp ) ABECABCDFG $.
      $( [8-Jun-94] $)
  $}


  ${
    intnan.1 $e |- -. ph $.
    $( Introduction of conjunct inside of a contradiction. $)
    intnan $p |- -. ( ps /\ ph ) $=
      ( wa pm3.27 mto ) BADACBAEF $.
      $( [16-Sep-93] $)
  $}

  ${
    intnanr.1 $e |- -. ph $.
    $( Introduction of conjunct inside of a contradiction. $)
    intnanr $p |- -. ( ph /\ ps ) $=
      ( wa pm3.26 mto ) ABDACABEF $.
      $( [3-Apr-95] $)
  $}

  ${
    mpan.1 $e |- ph $.
    mpan.2 $e |- ( ( ph /\ ps ) -> ch ) $.
    $( An inference based on modus ponens. $)
    mpan $p |- ( ps -> ch ) $=
      ( wi exp ax-mp ) ABCFDABCEGH $.
      $( [30-Aug-93] $)
  $}

  ${
    mpan2.1 $e |- ps $.
    mpan2.2 $e |- ( ( ph /\ ps ) -> ch ) $.
    $( An inference based on modus ponens. $)
    mpan2 $p |- ( ph -> ch ) $=
      ( exp mpi ) ABCDABCEFG $.
      $( [16-Sep-93] $)
  $}

  ${
    mp2an.1 $e |- ph $.
    mp2an.2 $e |- ps $.
    mp2an.3 $e |- ( ( ph /\ ps ) -> ch ) $.
    $( An inference based on modus ponens. $)
    mp2an $p |- ch $=
      ( mpan ax-mp ) BCEABCDFGH $.
      $( [13-Apr-95] $)
  $}

  ${
    mpani.1 $e |- ps $.
    mpani.2 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    $( An inference based on modus ponens. $)
    mpani $p |- ( ph -> ( ch -> th ) ) $=
      ( wi exp3a mpi ) ABCDGEABCDFHI $.
      $( [10-Apr-94] $)
  $}

  ${
    mpan2i.1 $e |- ch $.
    mpan2i.2 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    $( An inference based on modus ponens. $)
    mpan2i $p |- ( ph -> ( ps -> th ) ) $=
      ( exp3a mpii ) ABCDEABCDFGH $.
      $( [10-Apr-94] $)
  $}

  ${
    mp2ani.1 $e |- ps $.
    mp2ani.2 $e |- ch $.
    mp2ani.3 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    $( An inference based on modus ponens. $)
    mp2ani $p |- ( ph -> th ) $=
      ( mpani mpi ) ACDFABCDEGHI $.
      $( [13-Dec-04] $) $( [12-Dec-04] $)
  $}

  ${
    mpand.1 $e |- ( ph -> ps ) $.
    mpand.2 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    $( A deduction based on modus ponens. $)
    mpand $p |- ( ph -> ( ch -> th ) ) $=
      ( wi exp3a mpd ) ABCDGEABCDFHI $.
      $( [13-Dec-04] $) $( [12-Dec-04] $)
  $}

  ${
    mpan2d.1 $e |- ( ph -> ch ) $.
    mpan2d.2 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    $( A deduction based on modus ponens. $)
    mpan2d $p |- ( ph -> ( ps -> th ) ) $=
      ( exp3a mpid ) ABCDEABCDFGH $.
      $( [13-Dec-04] $) $( [12-Dec-04] $)
  $}

  ${
    mp2and.1 $e |- ( ph -> ps ) $.
    mp2and.2 $e |- ( ph -> ch ) $.
    mp2and.3 $e |- ( ph -> ( ( ps /\ ch ) -> th ) ) $.
    $( A deduction based on modus ponens. $)
    mp2and $p |- ( ph -> th ) $=
      ( mpand mpd ) ACDFABCDEGHI $.
      $( [13-Dec-04] $) $( [12-Dec-04] $)
  $}

  ${
    mpdan.1 $e |- ( ph -> ps ) $.
    mpdan.2 $e |- ( ( ph /\ ps ) -> ch ) $.
    $( An inference based on modus ponens. $)
    mpdan $p |- ( ph -> ch ) $=
      ( exp mpd ) ABCDABCEFG $.
      $( [23-May-99] $)
  $}

  ${
    mpancom.1 $e |- ( ps -> ph ) $.
    mpancom.2 $e |- ( ( ph /\ ps ) -> ch ) $.
    $( An inference based on modus ponens with commutation of antecedents. $)
    mpancom $p |- ( ps -> ch ) $=
      ( ancoms mpdan ) BACDABCEFG $.
      $( [13-Mar-04] $) $( [28-Oct-03] $)
  $}

  ${
    mpan11.1 $e |- ph $.
    mpan11.2 $e |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $.
    $( An inference based on modus ponens. $)
    mpan11 $p |- ( ( ps /\ ch ) -> th ) $=
      ( wi wa exp mpan imp ) BCDABCDGEABHCDFIJK $.
      $( [16-Aug-94] $)
  $}

  ${
    mpan12.1 $e |- ps $.
    mpan12.2 $e |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $.
    $( An inference based on modus ponens. $)
    mpan12 $p |- ( ( ph /\ ch ) -> th ) $=
      ( wi wa exp mpan2 imp ) ACDABCDGEABHCDFIJK $.
      $( [16-Aug-94] $)
  $}

  ${
    mpan21.1 $e |- ps $.
    mpan21.2 $e |- ( ( ph /\ ( ps /\ ch ) ) -> th ) $.
    $( An inference based on modus ponens. $)
    mpan21 $p |- ( ( ph /\ ch ) -> th ) $=
      ( wa exp mpani imp ) ACDABCDEABCGDFHIJ $.
      $( [3-May-94] $)
  $}

  ${
    mpan22.1 $e |- ch $.
    mpan22.2 $e |- ( ( ph /\ ( ps /\ ch ) ) -> th ) $.
    $( An inference based on modus ponens. $)
    mpan22 $p |- ( ( ph /\ ps ) -> th ) $=
      ( wa exp mpan2i imp ) ABDABCDEABCGDFHIJ $.
      $( [3-May-94] $)
  $}

  ${
    mpan121.1 $e |- ps $.
    mpan121.2 $e |- ( ( ( ph /\ ( ps /\ ch ) ) /\ th ) -> ta ) $.
    $( An inference based on modus ponens. $)
    mpan121 $p |- ( ( ( ph /\ ch ) /\ th ) -> ta ) $=
      ( wa wi exp mpan21 imp ) ACHDEABCDEIFABCHHDEGJKL $.
      $( [7-Jan-05] $) $( [30-Dec-04] $)
  $}

  $( Modus-tollens-like theorem. $)
  mtt $p |- ( -. ph -> ( -. ps <-> ( ps -> ph ) ) ) $=
    ( wn wi pm2.21 a1i con3 com12 impbid ) ACZBCZBADZKLDJBAEFLJKBAGHI $.
    $( [7-Apr-01] $)

  ${
    mt2bi.1 $e |- ph $.
    $( A false consequent falsifies an antecedent. $)
    mt2bi $p |- ( -. ps <-> ( ps -> -. ph ) ) $=
      ( wn wi pm2.21 con2 mpi impbi ) BDZBADZEZBKFLAJCBAGHI $.
      $( [19-Aug-93] $)
  $}

  ${
    mtbid.min $e |- ( ph -> -. ps ) $.
    mtbid.maj $e |- ( ph -> ( ps <-> ch ) ) $.
    $( A deduction from a biconditional, similar to modus tollens. $)
    mtbid $p |- ( ph -> -. ch ) $=
      ( biimprd mtod ) ACBDABCEFG $.
      $( [26-Nov-95] $)
  $}

  ${
    mtbird.min $e |- ( ph -> -. ch ) $.
    mtbird.maj $e |- ( ph -> ( ps <-> ch ) ) $.
    $( A deduction from a biconditional, similar to modus tollens. $)
    mtbird $p |- ( ph -> -. ps ) $=
      ( biimpd mtod ) ABCDABCEFG $.
      $( [10-May-94] $)
  $}

  ${
    mtbii.min $e |- -. ps $.
    mtbii.maj $e |- ( ph -> ( ps <-> ch ) ) $.
    $( An inference from a biconditional, similar to modus tollens. $)
    mtbii $p |- ( ph -> -. ch ) $=
      ( biimprd mtoi ) ACBDABCEFG $.
      $( [27-Nov-95] $)
  $}

  ${
    mtbiri.min $e |- -. ch $.
    mtbiri.maj $e |- ( ph -> ( ps <-> ch ) ) $.
    $( An inference from a biconditional, similar to modus tollens. $)
    mtbiri $p |- ( ph -> -. ps ) $=
      ( biimpd mtoi ) ABCDABCEFG $.
      $( [24-Aug-95] $)
  $}

  ${
    2th.1 $e |- ph $.
    2th.2 $e |- ps $.
    $( Two truths are equivalent. $)
    2th $p |- ( ph <-> ps ) $=
      ( a1i impbi ) ABBADEABCEF $.
      $( [18-Aug-93] $)
  $}

  ${
    tbt.1 $e |- ph $.
    $( A wff is equivalent to its equivalence with truth. $)
    tbt $p |- ( ps <-> ( ps <-> ph ) ) $=
      ( wb a1i a1d ax-1 impbid bi2 mpi impbi ) BBADZBBABABABCEFBAGHLABCBAIJK $.
      $( [18-Aug-93] $)
  $}

  ${
    nbn.1 $e |- -. ph $.
    $( The negation of a wff is equivalent to the wff's equivalence to
       falsehood. $)
    nbn $p |- ( -. ps <-> ( ps <-> ph ) ) $=
      ( wn wb pm2.21 a1i pm2.21d impbid bi1 mtoi impbi ) BDZBAEZMBABAFMABADMCGH
      INBACBAJKL $.
      $( [5-Aug-93] $)
  $}

  ${
    biantru.1 $e |- ph $.
    $( A wff is equivalent to its conjunction with truth. $)
    biantru $p |- ( ps <-> ( ps /\ ph ) ) $=
      ( wa wb iba ax-mp ) ABBADECABFG $.
      $( [5-Aug-93] $)
  $}

  ${
    biantrur.1 $e |- ph $.
    $( A wff is equivalent to its conjunction with truth. $)
    biantrur $p |- ( ps <-> ( ph /\ ps ) ) $=
      ( wa wb ibar ax-mp ) ABABDECABFG $.
      $( [3-Aug-94] $)
  $}

  ${
    biantrud.1 $e |- ( ph -> ps ) $.
    $( A wff is equivalent to its conjunction with truth. $)
    biantrud $p |- ( ph -> ( ch <-> ( ch /\ ps ) ) ) $=
      ( wa anim2i exp com12 wi pm3.26 a1i impbid ) ACCBEZCAMCAMABCDFGHMCIACBJKL
      $.
      $( [2-Aug-94] $)
  $}

  ${
    biantrurd.1 $e |- ( ph -> ps ) $.
    $( A wff is equivalent to its conjunction with truth. $)
    biantrurd $p |- ( ph -> ( ch <-> ( ps /\ ch ) ) ) $=
      ( wa biantrud ancom syl6bb ) ACCBEBCEABCDFCBGH $.
      $( [1-May-95] $)
  $}

  ${
    mpbiran.1 $e |- ( ph <-> ( ps /\ ch ) ) $.
    mpbiran.2 $e |- ps $.
    $( Detach truth from conjunction in biconditional. $)
    mpbiran $p |- ( ph <-> ch ) $=
      ( wa biantrur bitr4 ) ABCFCDBCEGH $.
      $( [27-Feb-96] $)
  $}

  ${
    mpbiranr.1 $e |- ( ph <-> ( ps /\ ch ) ) $.
    mpbiranr.2 $e |- ch $.
    $( Detach truth from conjunction in biconditional. $)
    mpbiranr $p |- ( ph <-> ps ) $=
      ( wa biantru bitr4 ) ABCFBDCBEGH $.
      $( [22-Feb-96] $)
  $}

  $( A wff is equivalent to itself with true antecedent. $)
  biimt $p |- ( ph -> ( ps <-> ( ph -> ps ) ) ) $=
    ( wi ax-1 a1i pm2.27 impbid ) ABABCZBHCABADEABFG $.
    $( [28-Jan-96] $)


  $( A wff is disjoined with truth is true. $)
  biort $p |- ( ph -> ( ph <-> ( ph \/ ps ) ) ) $=
    ( wo orc a1d ax-1 impbid ) AAABCZAHAABDEAHFG $.
    $( [23-May-99] $)

  $( A wff is equivalent to its disjunction with falsehood.  Theorem *4.74 of
     [WhiteheadRussell] p. 121. $)
  biorf $p |- ( -. ph -> ( ps <-> ( ph \/ ps ) ) ) $=
    ( wn wi wo biimt df-or syl6bbr ) ACZBIBDABEIBFABGH $.
    $( [23-Mar-95] $)

  ${
    biorfi.1 $e |- -. ph $.
    $( A wff is equivalent to its disjunction with falsehood. $)
    biorfi $p |- ( ps <-> ( ps \/ ph ) ) $=
      ( wo wn wb biorf ax-mp orcom bitr ) BABDZBADAEBKFCABGHABIJ $.
      $( [23-Mar-95] $)
  $}

  ${
    bianfi.1 $e |- -. ph $.
    $( A wff conjoined with falsehood is false. $)
    bianfi $p |- ( ph <-> ( ps /\ ph ) ) $=
      ( wa pm2.21i pm3.27 impbi ) ABADZAHCEBAFG $.
      $( [5-Aug-93] $)
  $}

  ${
    bianfd.1 $e |- ( ph -> -. ps ) $.
    $( A wff conjoined with falsehood is false. $)
    bianfd $p |- ( ph -> ( ps <-> ( ps /\ ch ) ) ) $=
      ( wa pm2.21d wi pm3.26 a1i impbid ) ABBCEZABKDFKBGABCHIJ $.
      $( [27-Mar-95] $)
  $}

  $( Negation inferred from embedded conjunct. $)
  pclem6 $p |- ( ( ph <-> ( ps /\ -. ph ) ) -> -. ps ) $=
    ( wn wa wb bi1 pm3.27 syl6 pm2.01d wi bi2 exp3a com23 con3 syli mpd ) ABACZ
    DZEZQBCZSASARQARFBQGHIQSBAJTSBQASBQAARKLMBANOP $.
    $( [20-Aug-93] $)

  $( A transitive law of equivalence.  Compare Theorem *4.22 of
     [WhiteheadRussell] p. 117. $)
  biantr $p |- ( ( ( ph <-> ps ) /\ ( ch <-> ps ) ) -> ( ph <-> ch ) ) $=
    ( wb id bibi2d biimparc ) CBDZACDABDHCBAHEFG $.
    $( [18-Aug-93] $)

  $( Removal of conjunct from one side of an equivalence. $)
  bimsc1 $p |- ( ( ( ph -> ps ) /\ ( ch <-> ( ps /\ ph ) ) )
               -> ( ch <-> ph ) ) $=
    ( wa wb wi id pm4.71r biimp bicomd sylan9bbr ) CBADZEZCLABFZAMGNALNALEABHIJ
    K $.
    $( [5-Aug-93] $)

  ${
    ecase2d.1 $e |- ( ph -> ps ) $.
    ecase2d.2 $e |- ( ph -> -. ( ps /\ ch ) ) $.
    ecase2d.3 $e |- ( ph -> -. ( ps /\ th ) ) $.
    ecase2d.4 $e |- ( ph -> ( ta \/ ( ch \/ th ) ) ) $.
    $( Deduction for elimination by cases. $)
    ecase2d $p |- ( ph -> ta ) $=
      ( wo wn wa wi imnan sylibr mpd jca ioran orcom sylib ord ) ACDJZKZEACKZDK
      ZLUCAUDUEABUDFABCLKBUDMGBCNOPABUEFABDLKBUEMHBDNOPQCDROAUBEAEUBJUBEJIEUBST
      UAP $.
      $( [21-Apr-94] $)
  $}

  ${
    ecase3.1 $e |- ( ph -> ch ) $.
    ecase3.2 $e |- ( ps -> ch ) $.
    ecase3.3 $e |- ( -. ( ph \/ ps ) -> ch ) $.
    $( Inference for elimination by cases. $)
    ecase3 $p |- ch $=
      ( wn wa wo ioran sylbir exp pm2.61ii ) ABCAGZBGZCNOHABIGCABJFKLDEM $.
      $( [23-Mar-95] $)
  $}

  ${
    ecase3d.1 $e |- ( ph -> ( ps -> th ) ) $.
    ecase3d.2 $e |- ( ph -> ( ch -> th ) ) $.
    ecase3d.3 $e |- ( ph -> ( -. ( ps \/ ch ) -> th ) ) $.
    $( Deduction for elimination by cases. $)
    ecase3d $p |- ( ph -> th ) $=
      ( wi com12 wo wn ecase3 ) BCADHABDEIACDFIABCJKDGIL $.
      $( [2-May-96] $)
  $}

  $( Lemma for combining cases. $)
  caselem $p |- ( ( ( ph \/ ps ) /\ ( ch \/ th ) ) <->
  ( ( ( ph /\ ch ) \/ ( ps /\ ch ) ) \/ ( ( ph /\ th ) \/ ( ps /\ th ) ) ) ) $=
    ( wo wa andi andir orbi12i bitr ) ABEZCDEFKCFZKDFZEACFBCFEZADFBDFEZEKCDGLNM
    OABCHABDHIJ $.
    $( [29-Jul-99] $)

  ${
    ccase.1 $e |- ( ( ph /\ ps ) -> ta ) $.
    ccase.2 $e |- ( ( ch /\ ps ) -> ta ) $.
    ccase.3 $e |- ( ( ph /\ th ) -> ta ) $.
    ccase.4 $e |- ( ( ch /\ th ) -> ta ) $.
    $( Inference for combining cases. $)
    ccase $p |- ( ( ( ph \/ ch ) /\ ( ps \/ th ) ) -> ta ) $=
      ( wo wa caselem jaoi sylbi ) ACJBDJKABKZCBKZJZADKZCDKZJZJEACBDLQETOEPFGMR
      ESHIMMN $.
      $( [29-Jul-99] $)
  $}

  ${
    $v et $. $( Greek eta $)
    ccasedwet $f wff et $.
    ccased.1 $e |- ( ph -> ( ( ps /\ ch ) -> et ) ) $.
    ccased.2 $e |- ( ph -> ( ( th /\ ch ) -> et ) ) $.
    ccased.3 $e |- ( ph -> ( ( ps /\ ta ) -> et ) ) $.
    ccased.4 $e |- ( ph -> ( ( th /\ ta ) -> et ) ) $.
    $( Deduction for combining cases. $)
    ccased $p |- ( ph -> ( ( ( ps \/ th ) /\ ( ch \/ ta ) ) -> et ) ) $=
      ( wa wo jaod caselem syl5ib ) ABCKZDCKZLZBEKZDEKZLZLFBDLCELKARFUAAPFQGHMA
      SFTIJMMBDCENO $.
      $( [10-May-04] $) $( [9-May-04] $)
  $}

  ${
    ccase2.1 $e |- ( ( ph /\ ps ) -> ta ) $.
    ccase2.2 $e |- ( ch -> ta ) $.
    ccase2.3 $e |- ( th -> ta ) $.
    $( Inference for combining cases. $)
    ccase2 $p |- ( ( ( ph \/ ch ) /\ ( ps \/ th ) ) -> ta ) $=
      ( adantr adantl ccase ) ABCDEFCEBGIDEAHJDECHJK $.
      $( [29-Jul-99] $)
  $}

  ${
    4cases.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    4cases.2 $e |- ( ( ph /\ -. ps ) -> ch ) $.
    4cases.3 $e |- ( ( -. ph /\ ps ) -> ch ) $.
    4cases.4 $e |- ( ( -. ph /\ -. ps ) -> ch ) $.
    $( Inference eliminating two antecedents from the four possible cases that
       result from their true/false combinations. $)
    4cases $p |- ch $=
      ( pm2.61an1 wn pm2.61i ) BCABCDFHABICEGHJ $.
      $( [25-Oct-03] $) $( [25-Oct-03] $)
  $}

  ${
    niabn.1 $e |- ph $.
    $( Miscellaneous inference relating falsehoods. $)
    niabn $p |- ( -. ps -> ( ( ch /\ ps ) <-> -. ph ) ) $=
      ( wa wn pm3.27 pm2.21ni pm5.21ni ) CBEBAFCBGABDHI $.
      $( [31-Mar-94] $)
  $}

  $( Lemma for an alternate version of weak deduction theorem. $)
  dedlem0a $p |- ( ph -> ( ps <-> ( ( ch -> ph ) -> ( ps /\ ph ) ) ) ) $=
    ( wi wa ax-1 a1i syl4 com12 impbid iba imbi2d bitrd ) ABCADZBDZNBAEZDABOBOD
    ABNFGOABANBACFHIJABPNABKLM $.
    $( [2-Apr-94] $)

  $( Lemma for an alternate version of weak deduction theorem. $)
  dedlem0b $p |- ( -. ph -> ( ps <-> ( ( ps -> ph ) -> ( ch /\ ph ) ) ) ) $=
    ( wn wi wa pm2.21 syl3d com23 pm3.27 syl34 con1d com12 impbid ) ADZBBAEZCAF
    ZEZOPBQOAQBAQGHIROBRBABDPQABAGCAJKLMN $.
    $( [2-Apr-94] $)

  $( Lemma for weak deduction theorem. $)
  dedlema $p |- ( ph -> ( ps <-> ( ( ps /\ ph ) \/ ( ch /\ -. ph ) ) ) ) $=
    ( wn wa wo wi orc a1i idd pm2.24 adantld jaod impbid iba orbi1d bitrd ) ABB
    CADZEZFZBAEZSFABTBTGABSHIABBSABJARBCABKLMNABUASABOPQ $.
    $( [26-Jun-02] $)

  $( Lemma for weak deduction theorem. $)
  dedlemb $p |- ( -. ph -> ( ch <-> ( ( ps /\ ph ) \/ ( ch /\ -. ph ) ) ) ) $=
    ( wn wa wo pm3.21 olc syl6 wi pm2.21 com23 imp3a pm3.26 a1i jaod impbid )
    ADZCBAEZCREZFZRCTUARCGTSHIRSCTRBACRABCABCJKLMTCJRCRNOPQ $.
    $( [15-May-99] $)

  ${
    elimh.1 $e |- ( ( ph <-> ( ( ph /\ ch ) \/ ( ps /\ -. ch ) ) )
                     -> ( ch <-> ta ) ) $.
    elimh.2 $e |- ( ( ps <-> ( ( ph /\ ch ) \/ ( ps /\ -. ch ) ) )
                     -> ( th <-> ta ) ) $.
    elimh.3 $e |- th $.
    $( Hypothesis builder for weak deduction theorem.  For more information,
       see the Deduction Theorem link on the Metamath Proof Explorer home
       page.  $)
    elimh $p |- ta $=
      ( wa wn wo wb dedlema syl ibi dedlemb mpbii pm2.61i ) CECECAACIBCJZIKZLCE
      LCABMFNOSDEHSBTLDELCABPGNQR $.
      $( [26-Jun-02] $)
  $}

  ${
    dedt.1 $e |- ( ( ph <-> ( ( ph /\ ch ) \/ ( ps /\ -. ch ) ) )
                     -> ( th <-> ta ) ) $.
    dedt.2 $e |- ta $.
    $( The weak deduction theorem.  For more information, see the Deduction
       Theorem link on the Metamath Proof Explorer home page.  $)
    dedt $p |- ( ch -> th ) $=
      ( wa wn wo wb dedlema mpbiri syl ) CAACHBCIHJKZDCABLODEGFMN $.
      $( [26-Jun-02] $)
  $}

  $( Contraposition.  Theorem *2.16 of [WhiteheadRussell] p. 103.  This version
     of ~ con3 demonstrates the use of the weak deduction theorem to derive
     it from ~ con3i . $)
  con3th $p |- ( ( ph -> ps ) -> ( -. ps -> -. ph ) ) $=
    ( wi wn wa wo wb id negbid imbi1d imbi2d elimh con3i dedt ) BAABCZBDZADZCBO
    EAODEFZDZQCBRGZPSQTBRTHZIJARBAOAACARCTBRAUAKARGZARAUBHKAHLMN $.
    $( [27-Jun-02] $)

  $( The consensus theorem.  This theorem and its dual (with ` \/ ` and ` /\ `
     interchanged) are commonly used in computer logic design to eliminate
     redundant terms from Boolean expressions.  Specifically, we show the term
     ` ( ps /\ ch ) ` on the left-hand side is redundant. $)
  consensus $p |- ( ( ( ( ph /\ ps ) \/ ( -. ph /\ ch ) ) \/ ( ps /\ ch ) ) <->
                      ( ( ph /\ ps ) \/ ( -. ph /\ ch ) ) ) $=
    ( wa wn wo id wi dedlema biimpd adantrd dedlemb adantld pm2.61i ancom
    orbi12i sylib jaoi orc impbi ) ABDZAEZCDZFZBCDZFUDUDUDUEUDGUEBADZCUBDZFZUDA
    UEUHHABUHCABUHABCIJKUBCUHBUBCUHABCLJMNUFUAUGUCBAOCUBOPQRUDUEST $.
    $( [16-May-03] $)

  ${
    ninba.1 $e |- ph $.
    $( Miscellaneous inference relating falsehoods. $)
    ninba $p |- ( -. ps -> ( -. ph <-> ( ch /\ ps ) ) ) $=
      ( wn wa niabn bicomd ) BECBFAEABCDGH $.
      $( [31-Mar-94] $)
  $}

  ${
    $v et $. $( Greek eta $)
    wet $f wff et $.
    prlem1.1 $e |- ( ph -> ( et <-> ch ) ) $.
    prlem1.2 $e |- ( ps -> -. th ) $.
    $( A specialized lemma for set theory (axiom of pairing). $)
    prlem1 $p |- ( ph -> ( ps ->
                  ( ( ( ps /\ ch ) \/ ( th /\ ta ) ) -> et ) ) ) $=
      ( wa wo wi biimprcd adantl a1dd wn pm2.24 syl5 adantr a1d jaoi com3l ) BC
      IZDEIZJABFUBABFKZKUCUBAFBCAFKBAFCGLMNUCUDADUDEDDOFBDFPHQRSTUA $.
      $( [18-Oct-95] $)
  $}

  $( A specialized lemma for set theory (axiom of pairing). $)
  prlem2 $p |- ( ( ( ph /\ ps ) \/ ( ch /\ th ) ) <->
               ( ( ph \/ ch ) /\ ( ( ph /\ ps ) \/ ( ch /\ th ) ) ) ) $=
    ( wa wo oel anbi1i anass bitr orcom orbi12i andi bitr4 ) ABEZCDEZFZACFZOEZR
    PEZFRQEOSPTORAEZBESAUABACGHRABIJPRCEZDETCUBDCCAFZCEUBCAGUCRCCAKHJHRCDIJLROP
    MN $.
    $( [5-Aug-93] $)

  ${
    oplem1.1 $e |- ( ph -> ( ps \/ ch ) ) $.
    oplem1.2 $e |- ( ph -> ( th \/ ta ) ) $.
    oplem1.3 $e |- ( ps <-> th ) $.
    oplem1.4 $e |- ( ch -> ( th <-> ta ) ) $.
    $( A specialized lemma for set theory (ordered pair theorem). $)
    oplem1 $p |- ( ph -> ps ) $=
      ( wn wi wa ord negbii syl5ib jcad syl5bb biimpar syl6 pm2.18 syl ) ABJZBK
      BAUBCELBAUBCEABCFMADJEUBADEGMBDHNOPCBECDEBIHQRSBTUA $.
      $( [18-Oct-95] $)
  $}

  $( Lemma used in construction of real numbers. $)
  rnlem $p |- ( ( ( ph /\ ps ) /\ ( ch /\ th ) ) <->
  ( ( ( ph /\ ch ) /\ ( ps /\ th ) ) /\ ( ( ph /\ th ) /\ ( ps /\ ch ) ) ) ) $=
    ( wa anandir anandi anbi12i ancom anbi2i an4 bitr 3bitr ) ABECDEZEANEZBNEZE
    ACEZADEZEZBCEZBDEZEZEZQUAERTEEZABNFOSPUBACDGBCDGHUCSUATEZEUDUBUESTUAIJQRUAT
    KLM $.
    $( [4-Sep-95] $)

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Abbreviated conjunction and disjunction of three wff's
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( Extend wff definition to include 3-way disjunction ('or'). $)
  w3o $a wff ( ph \/ ps \/ ch ) $.
  $( Extend wff definition to include 3-way conjunction ('and'). $)
  w3a $a wff ( ph /\ ps /\ ch ) $.

  $( These abbreviations help eliminate parentheses to aid readability. $)

  $( Define disjunction ('or') of 3 wff's.  Definition *2.33 of
     [WhiteheadRussell] p. 105.  This abbreviation reduces the number of
     parentheses and emphasizes that the order of bracketing is not
     important by virtue of the associative law ~ orass . $)
  df-3or $a |- ( ( ph \/ ps \/ ch ) <-> ( ( ph \/ ps ) \/ ch ) ) $.

  $( Define conjunction ('and') of 3 wff.s.  Definition *4.34 of
     [WhiteheadRussell] p. 118.  This abbreviation reduces the number of
     parentheses and emphasizes that the order of bracketing is not
     important by virtue of the associative law ~ anass . $)
  df-3an $a |- ( ( ph /\ ps /\ ch ) <-> ( ( ph /\ ps ) /\ ch ) ) $.

  $( Associative law for triple disjunction. $)
  3orass $p |- ( ( ph \/ ps \/ ch ) <-> ( ph \/ ( ps \/ ch ) ) ) $=
    ( w3o wo df-3or orass bitr ) ABCDABECEABCEEABCFABCGH $.
    $( [8-Apr-94] $)

  $( Associative law for triple conjunction. $)
  3anass $p |- ( ( ph /\ ps /\ ch ) <-> ( ph /\ ( ps /\ ch ) ) ) $=
    ( w3a wa df-3an anass bitr ) ABCDABECEABCEEABCFABCGH $.
    $( [8-Apr-94] $)

  $( Rotation law for triple conjunction. $)
  3anrot $p |- ( ( ph /\ ps /\ ch ) <-> ( ps /\ ch /\ ph ) ) $=
    ( wa w3a ancom 3anass df-3an 3bitr4 ) ABCDZDJADABCEBCAEAJFABCGBCAHI $.
    $( [8-Apr-94] $)

  $( Rotation law for triple disjunction. $)
  3orrot $p |- ( ( ph \/ ps \/ ch ) <-> ( ps \/ ch \/ ph ) ) $=
    ( wo w3o orcom 3orass df-3or 3bitr4 ) ABCDZDJADABCEBCAEAJFABCGBCAHI $.
    $( [4-Apr-95] $)

  $( Commutation law for triple conjunction. $)
  3ancoma $p |- ( ( ph /\ ps /\ ch ) <-> ( ps /\ ph /\ ch ) ) $=
    ( wa w3a ancom anbi1i df-3an 3bitr4 ) ABDZCDBADZCDABCEBACEJKCABFGABCHBACHI
    $.
    $( [21-Apr-94] $)

  $( Commutation law for triple conjunction. $)
  3ancomb $p |- ( ( ph /\ ps /\ ch ) <-> ( ph /\ ch /\ ps ) ) $=
    ( w3a 3ancoma 3anrot bitr ) ABCDBACDACBDABCEBACFG $.
    $( [21-Apr-94] $)

  $( Reversal law for triple conjunction. $)
  3anrev $p |- ( ( ph /\ ps /\ ch ) <-> ( ch /\ ps /\ ph ) ) $=
    ( w3a 3ancoma 3anrot bitr4 ) ABCDBACDCBADABCECBAFG $.
    $( [21-Apr-94] $)

  $( Simplification of triple conjunction. $)
  3simpa $p |- ( ( ph /\ ps /\ ch ) -> ( ph /\ ps ) ) $=
    ( w3a wa df-3an pm3.26bd ) ABCDABECABCFG $.
    $( [21-Apr-94] $)

  $( Simplification of triple conjunction. $)
  3simpb $p |- ( ( ph /\ ps /\ ch ) -> ( ph /\ ch ) ) $=
    ( w3a wa 3ancomb 3simpa sylbi ) ABCDACBDACEABCFACBGH $.
    $( [21-Apr-94] $)

  $( Simplification of triple conjunction. $)
  3simpc $p |- ( ( ph /\ ps /\ ch ) -> ( ps /\ ch ) ) $=
    ( w3a wa 3anrot 3simpa sylbi ) ABCDBCADBCEABCFBCAGH $.
    $( [21-Apr-94] $)

  $( Simplification of triple conjunction. $)
  3simp1 $p |- ( ( ph /\ ps /\ ch ) -> ph ) $=
    ( w3a 3simpa pm3.26d ) ABCDABABCEF $.
    $( [21-Apr-94] $)

  $( Simplification of triple conjunction. $)
  3simp2 $p |- ( ( ph /\ ps /\ ch ) -> ps ) $=
    ( w3a 3simpa pm3.27d ) ABCDABABCEF $.
    $( [21-Apr-94] $)

  $( Simplification of triple conjunction. $)
  3simp3 $p |- ( ( ph /\ ps /\ ch ) -> ch ) $=
    ( w3a 3simpc pm3.27d ) ABCDBCABCEF $.
    $( [21-Apr-94] $)

  ${
    3adant.1 $e |- ( ( ph /\ ps ) -> ch ) $.
    $( Deduction adding a conjunct to an antecedent. $)
    3adant1 $p |- ( ( th /\ ph /\ ps ) -> ch ) $=
      ( w3a wa 3simpc syl ) DABFABGCDABHEI $.
      $( [16-Jul-95] $)

    $( Deduction adding a conjunct to an antecedent. $)
    3adant2 $p |- ( ( ph /\ th /\ ps ) -> ch ) $=
      ( w3a wa 3simpb syl ) ADBFABGCADBHEI $.
      $( [16-Jul-95] $)

    $( Deduction adding a conjunct to an antecedent. $)
    3adant3 $p |- ( ( ph /\ ps /\ th ) -> ch ) $=
      ( w3a wa 3simpa syl ) ABDFABGCABDHEI $.
      $( [16-Jul-95] $)
  $}

  ${
    3adantl.1 $e |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $.
    $( Deduction adding a conjunct to an antecedent. $)
    3adantl1 $p |- ( ( ( ta /\ ph /\ ps ) /\ ch ) -> th ) $=
      ( w3a wi wa exp 3adant1 imp ) EABGCDABCDHEABICDFJKL $.
      $( [26-Feb-05] $) $( [24-Feb-05] $)

    $( Deduction adding a conjunct to an antecedent. $)
    3adantl2 $p |- ( ( ( ph /\ ta /\ ps ) /\ ch ) -> th ) $=
      ( w3a wi wa exp 3adant2 imp ) AEBGCDABCDHEABICDFJKL $.
      $( [25-Feb-05] $)

  $}

  $( Introduction in triple disjunction. $)
  3mix1 $p |- ( ph -> ( ph \/ ps \/ ch ) ) $=
    ( wo w3o orc 3orass sylibr ) AABCDZDABCEAIFABCGH $.
    $( [4-Apr-95] $)

  $( Introduction in triple disjunction. $)
  3mix2 $p |- ( ph -> ( ps \/ ph \/ ch ) ) $=
    ( w3o 3mix1 3orrot sylibr ) AACBDBACDACBEBACFG $.
    $( [4-Apr-95] $)

  $( Introduction in triple disjunction. $)
  3mix3 $p |- ( ph -> ( ps \/ ch \/ ph ) ) $=
    ( w3o 3mix1 3orrot sylib ) AABCDBCADABCEABCFG $.
    $( [4-Apr-95] $)

  ${
    3pm3.2i.1 $e |- ph $.
    3pm3.2i.2 $e |- ps $.
    3pm3.2i.3 $e |- ch $.
    $( Infer conjunction of premises. $)
    3pm3.2i $p |- ( ph /\ ps /\ ch ) $=
      ( w3a wa pm3.2i df-3an mpbir ) ABCGABHZCHLCABDEIFIABCJK $.
      $( [10-Feb-95] $)
  $}

  ${
    3jca.1 $e |- ( ph -> ps ) $.
    3jca.2 $e |- ( ph -> ch ) $.
    3jca.3 $e |- ( ph -> th ) $.
    $( Join consequents with conjunction. $)
    3jca $p |- ( ph -> ( ps /\ ch /\ th ) ) $=
      ( wa w3a jca df-3an sylibr ) ABCHZDHBCDIAMDABCEFJGJBCDKL $.
      $( [9-Apr-94] $)
  $}

  ${
    $v et $. $( Greek eta $)
    i3wet $f wff et $.
    3anim123i.1 $e |- ( ph -> ps ) $.
    3anim123i.2 $e |- ( ch -> th ) $.
    3anim123i.3 $e |- ( ta -> et ) $.
    $( Join antecedents and consequents with conjunction. $)
    3anim123i $p |- ( ( ph /\ ch /\ ta ) -> ( ps /\ th /\ et ) ) $=
      ( wa w3a anim12i df-3an 3imtr4 ) ACJZEJBDJZFJACEKBDFKOPEFABCDGHLILACEMBDF
      MN $.
      $( [8-Apr-94] $)
  $}

  ${
    $v et $. $( Greek eta $)
    b3wet $f wff et $.
    bi3.1 $e |- ( ph <-> ps ) $.
    bi3.2 $e |- ( ch <-> th ) $.
    bi3.3 $e |- ( ta <-> et ) $.

    $( Join 3 biconditionals with conjunction. $)
    3anbi123i $p |- ( ( ph /\ ch /\ ta ) <-> ( ps /\ th /\ et ) ) $=
      ( wa w3a anbi12i df-3an 3bitr4 ) ACJZEJBDJZFJACEKBDFKOPEFABCDGHLILACEMBDF
      MN $.
      $( [21-Apr-94] $)

    $( Join 3 biconditionals with disjunction. $)
    3orbi123i $p |- ( ( ph \/ ch \/ ta ) <-> ( ps \/ th \/ et ) ) $=
      ( wo w3o orbi12i df-3or 3bitr4 ) ACJZEJBDJZFJACEKBDFKOPEFABCDGHLILACEMBDF
      MN $.
      $( [17-May-94] $)
  $}

  ${
    3imp.1 $e |- ( ph -> ( ps -> ( ch -> th ) ) ) $.
    $( Importation inference. $)
    3imp $p |- ( ( ph /\ ps /\ ch ) -> th ) $=
      ( w3a wa df-3an imp31 sylbi ) ABCFABGCGDABCHABCDEIJ $.
      $( [8-Apr-94] $)
  $}

  ${
    3impa.1 $e |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $.
    $( Importation from double to triple conjunction. $)
    3impa $p |- ( ( ph /\ ps /\ ch ) -> th ) $=
      ( exp31 3imp ) ABCDABCDEFG $.
      $( [20-Aug-95] $)
  $}

  ${
    3impb.1 $e |- ( ( ph /\ ( ps /\ ch ) ) -> th ) $.
    $( Importation from double to triple conjunction. $)
    3impb $p |- ( ( ph /\ ps /\ ch ) -> th ) $=
      ( exp32 3imp ) ABCDABCDEFG $.
      $( [20-Aug-95] $)
  $}

  ${
    3exp.1 $e |- ( ( ph /\ ps /\ ch ) -> th ) $.
    $( Exportation inference. $)
    3exp $p |- ( ph -> ( ps -> ( ch -> th ) ) ) $=
      ( wa w3a df-3an sylbir exp31 ) ABCDABFCFABCGDABCHEIJ $.
      $( [30-May-94] $)

    $( Exportation from triple to double conjunction. $)
    3expa $p |- ( ( ( ph /\ ps ) /\ ch ) -> th ) $=
      ( 3exp imp31 ) ABCDABCDEFG $.
      $( [20-Aug-95] $)

    $( Exportation from triple to double conjunction. $)
    3expb $p |- ( ( ph /\ ( ps /\ ch ) ) -> th ) $=
      ( 3exp imp32 ) ABCDABCDEFG $.
      $( [20-Aug-95] $)

    $( Commutation in antecedent.  Swap 1st and 3rd. $)
    3com12 $p |- ( ( ps /\ ph /\ ch ) -> th ) $=
      ( wi 3exp com12 3imp ) BACDABCDFABCDEGHI $.
      $( [28-Jan-96] $)

    $( Commutation in antecedent.  Swap 1st and 3rd. $)
    3com13 $p |- ( ( ch /\ ps /\ ph ) -> th ) $=
      ( w3a 3anrev sylbi ) CBAFABCFDCBAGEH $.
      $( [28-Jan-96] $)

    $( Commutation in antecedent.  Swap 2nd and 3rd. $)
    3com23 $p |- ( ( ph /\ ch /\ ps ) -> th ) $=
      ( 3exp com23 3imp ) ACBDABCDABCDEFGH $.
      $( [28-Jan-96] $)

    $( Commutation in antecedent.  Rotate left. $)
    3coml $p |- ( ( ps /\ ch /\ ph ) -> th ) $=
      ( 3com23 3com13 ) ACBDABCDEFG $.
      $( [28-Jan-96] $)

    $( Commutation in antecedent.  Rotate right. $)
    3comr $p |- ( ( ch /\ ph /\ ps ) -> th ) $=
      ( 3coml ) BCADABCDEFF $.
      $( [28-Jan-96] $)

  $}

  ${
    3imp1.1 $e |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $.
    $( Importation from double to triple conjunction. $)
    3imp1 $p |- ( ( ( ph /\ ps /\ ch ) /\ th ) -> ta ) $=
      ( w3a wi 3imp imp ) ABCGDEABCDEHFIJ $.
      $( [26-Feb-05] $) $( [24-Feb-05] $)
  $}

  ${
    3exp1.1 $e |- ( ( ( ph /\ ps /\ ch ) /\ th ) -> ta ) $.
    $( Importation from double to triple conjunction. $)
    3exp1 $p |- ( ph -> ( ps -> ( ch -> ( th -> ta ) ) ) ) $=
      ( wi w3a exp 3exp ) ABCDEGABCHDEFIJ $.
      $( [26-Feb-05] $) $( [24-Feb-05] $)
  $}

  ${
    syl3an.1 $e |- ( ( ph /\ ps /\ ch ) -> th ) $.
    ${
      syl3an1.2 $e |- ( ta -> ph ) $.
      $( A syllogism inference. $)
      syl3an1 $p |- ( ( ta /\ ps /\ ch ) -> th ) $=
        ( wa 3expb sylan 3impb ) EBCDABCHDEABCDFIGJK $.
        $( [22-Aug-95] $)
    $}

    ${
      syl3an2.2 $e |- ( ta -> ps ) $.
      $( A syllogism inference. $)
      syl3an2 $p |- ( ( ph /\ ta /\ ch ) -> th ) $=
        ( wi 3exp syl5 3imp ) AECDABCDHEABCDFIGJK $.
        $( [22-Aug-95] $)
    $}

    ${
      syl3an3.2 $e |- ( ta -> ch ) $.
      $( A syllogism inference. $)
      syl3an3 $p |- ( ( ph /\ ps /\ ta ) -> th ) $=
        ( 3exp syl7 3imp ) ABEDABCDEABCDFHGIJ $.
        $( [22-Aug-95] $)
    $}

    ${
      syl3an1b.2 $e |- ( ta <-> ph ) $.
      $( A syllogism inference. $)
      syl3an1b $p |- ( ( ta /\ ps /\ ch ) -> th ) $=
        ( biimp syl3an1 ) ABCDEFEAGHI $.
        $( [22-Aug-95] $)
    $}

    ${
      syl3an2b.2 $e |- ( ta <-> ps ) $.
      $( A syllogism inference. $)
      syl3an2b $p |- ( ( ph /\ ta /\ ch ) -> th ) $=
        ( biimp syl3an2 ) ABCDEFEBGHI $.
        $( [22-Aug-95] $)
    $}

    ${
      syl3an3b.2 $e |- ( ta <-> ch ) $.
      $( A syllogism inference. $)
      syl3an3b $p |- ( ( ph /\ ps /\ ta ) -> th ) $=
        ( biimp syl3an3 ) ABCDEFECGHI $.
        $( [22-Aug-95] $)
    $}

    ${
      syl3an1br.2 $e |- ( ph <-> ta ) $.
      $( A syllogism inference. $)
      syl3an1br $p |- ( ( ta /\ ps /\ ch ) -> th ) $=
        ( biimpr syl3an1 ) ABCDEFAEGHI $.
        $( [22-Aug-95] $)
    $}

    ${
      syl3an2br.2 $e |- ( ps <-> ta ) $.
      $( A syllogism inference. $)
      syl3an2br $p |- ( ( ph /\ ta /\ ch ) -> th ) $=
        ( biimpr syl3an2 ) ABCDEFBEGHI $.
        $( [22-Aug-95] $)
    $}

    ${
      syl3an3br.2 $e |- ( ch <-> ta ) $.
      $( A syllogism inference. $)
      syl3an3br $p |- ( ( ph /\ ps /\ ta ) -> th ) $=
        ( biimpr syl3an3 ) ABCDEFCEGHI $.
        $( [22-Aug-95] $)
    $}

    ${
      $v et $. $( Greek eta $)
      $v ze $. $( Greek zeta $)
      syl3an.we $f wff et $.
      syl3an.wz $f wff ze $.
      syl3an.2 $e |- ( ta -> ph ) $.
      syl3an.3 $e |- ( et -> ps ) $.
      syl3an.4 $e |- ( ze -> ch ) $.
      $( A triple syllogism inference. $)
      syl3an $p |- ( ( ta /\ et /\ ze ) -> th ) $=
        ( w3a 3anim123i syl ) EGHLABCLDEAGBHCIJKMFN $.
        $( [14-May-04] $) $( [13-May-04] $)
    $}
  $}

  ${
    $v et $. $( Greek eta $)
    syl3an11.we $f wff et $.
    syl3an11.1 $e |- ( ( ( ph /\ ps /\ ch ) /\ th ) -> ta ) $.
    ${
      syl3an11.2 $e |- ( et -> ph ) $.
    $}

    ${
      syl3an12.2 $e |- ( et -> ps ) $.
      $( A syllogism inference. $)
      syl3an12 $p |- ( ( ( ph /\ et /\ ch ) /\ th ) -> ta ) $=
        ( w3a wi exp syl3an2 imp ) AFCIDEABCDEJFABCIDEGKHLM $.
        $( [26-Feb-05] $) $( [24-Feb-05] $)
    $}

    ${
      syl3an13.2 $e |- ( et -> ch ) $.
    $}
  $}

  ${
    syl3anc.1 $e |- ( ( ph /\ ps /\ ch ) -> th ) $.
    syl3anc.2 $e |- ( ta -> ph ) $.
    syl3anc.3 $e |- ( ta -> ps ) $.
    syl3anc.4 $e |- ( ta -> ch ) $.
    $( A syllogism inference combined with contraction. $)
    syl3anc $p |- ( ta -> th ) $=
      ( w3a 3jca syl ) EABCJDEABCGHIKFL $.
      $( [2-Jan-05] $) $( [1-Jan-05] $)
  $}

  ${
    3impdi.1 $e |- ( ( ( ph /\ ps ) /\ ( ph /\ ch ) ) -> th ) $.
    $( Importation inference (undistribute conjunction). $)
    3impdi $p |- ( ( ph /\ ps /\ ch ) -> th ) $=
      ( anandis 3impb ) ABCDABCDEFG $.
      $( [14-Aug-95] $)
  $}

  ${
    3impdir.1 $e |- ( ( ( ph /\ ps ) /\ ( ch /\ ps ) ) -> th ) $.
    $( Importation inference (undistribute conjunction). $)
    3impdir $p |- ( ( ph /\ ch /\ ps ) -> th ) $=
      ( anandirs 3impa ) ACBDACBDEFG $.
      $( [20-Aug-95] $)
  $}

  $( Disjunction of 3 antecedents. $)
  3jao $p |- ( ( ( ph -> ps ) /\ ( ch -> ps ) /\ ( th -> ps ) ) ->
              ( ( ph \/ ch \/ th ) -> ps ) ) $=
    ( wi w3a wo w3o jao syl6 3imp df-3or syl5ib ) ABEZCBEZDBEZFACGZDGZBACDHNOPR
    BEZNOQBEPSEABCIQBDIJKACDLM $.
    $( [8-Apr-94] $)

  ${
    3jaoi.1 $e |- ( ph -> ps ) $.
    3jaoi.2 $e |- ( ch -> ps ) $.
    3jaoi.3 $e |- ( th -> ps ) $.
    $( Disjunction of 3 antecedents (inference). $)
    3jaoi $p |- ( ( ph \/ ch \/ th ) -> ps ) $=
      ( wi w3a w3o 3pm3.2i 3jao ax-mp ) ABHZCBHZDBHZIACDJBHNOPEFGKABCDLM $.
      $( [12-Sep-95] $)
  $}

  ${
    $v et $. $( Greek eta $)
    $v ze $. $( Greek zeta $)
    syl3an9b.we $f wff et $.
    syl3an9b.wz $f wff ze $.
    syl3an9b.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    syl3an9b.2 $e |- ( th -> ( ch <-> ta ) ) $.
    syl3an9b.3 $e |- ( et -> ( ta <-> ze ) ) $.
    $( Nested syllogism inference conjoining 3 dissimilar antecedents. $)
    syl3an9b $p |- ( ( ph /\ th /\ et ) -> ( ps <-> ze ) ) $=
      ( wb wa sylan9bb 3impa ) ADFBGKADLBEFGABCDEHIMJMN $.
      $( [1-May-95] $)
  $}

  ${
    $v et $. $( Greek eta $)
    $v ze $. $( Greek zeta $)
    bi3d.we $f wff et $.
    bi3d.wz $f wff ze $.
    bi3d.1 $e |- ( ph -> ( ps <-> ch ) ) $.
    bi3d.2 $e |- ( ph -> ( th <-> ta ) ) $.
    bi3d.3 $e |- ( ph -> ( et <-> ze ) ) $.
    $( Deduction joining 3 equivalences to form equivalence of disjunctions. $)
    3orbi123d $p |- ( ph -> ( ( ps \/ th \/ et ) <-> ( ch \/ ta \/ ze ) ) ) $=
      ( wo w3o orbi12d df-3or 3bitr4g ) ABDKZFKCEKZGKBDFLCEGLAPQFGABCDEHIMJMBDF
      NCEGNO $.
      $( [20-Apr-94] $)

    $( Deduction joining 3 equivalences to form equivalence of conjunctions. $)
    3anbi123d $p |- ( ph -> ( ( ps /\ th /\ et ) <-> ( ch /\ ta /\ ze ) ) ) $=
      ( wa w3a anbi12d df-3an 3bitr4g ) ABDKZFKCEKZGKBDFLCEGLAPQFGABCDEHIMJMBDF
      NCEGNO $.
      $( [22-Apr-94] $)
  $}

  ${
    $v et $. $( Greek eta $)
    $v ze $. $( Greek zeta $)
    im3d.we $f wff et $.
    im3d.wz $f wff ze $.
    im3d.1 $e |- ( ph -> ( ps -> ch ) ) $.
    im3d.2 $e |- ( ph -> ( th -> ta ) ) $.
    im3d.3 $e |- ( ph -> ( et -> ze ) ) $.

    $( Deduction joining 3 implications to form implication of disjunctions. $)
    3orim123d $p |- ( ph -> ( ( ps \/ th \/ et ) -> ( ch \/ ta \/ ze ) ) ) $=
      ( wo w3o orim12d df-3or 3imtr4g ) ABDKZFKCEKZGKBDFLCEGLAPQFGABCDEHIMJMBDF
      NCEGNO $.
      $( [4-Apr-97] $)
  $}

  ${
    $v et $. $( Greek eta $)
    an6wet $f wff et $.
    $( Rearrangement of 6 conjuncts. $)
    an6 $p |- ( ( ( ph /\ ps /\ ch ) /\ ( th /\ ta /\ et ) ) <->
              ( ( ph /\ th ) /\ ( ps /\ ta ) /\ ( ch /\ et ) ) ) $=
      ( w3a wa df-3an anbi12i an4 anbi1i 3bitr bitr4 ) ABCGZDEFGZHZADHZBEHZHZCF
      HZHZRSUAGQABHZCHZDEHZFHZHUCUEHZUAHUBOUDPUFABCIDEFIJUCCUEFKUGTUAABDEKLMRSU
      AIN $.
      $( [13-Mar-95] $)
  $}

  ${
    mp3an1.1 $e |- ph $.
    mp3an1.2 $e |- ( ( ph /\ ps /\ ch ) -> th ) $.
    $( An inference based on modus ponens. $)
    mp3an1 $p |- ( ( ps /\ ch ) -> th ) $=
      ( wa 3expb mpan ) ABCGDEABCDFHI $.
      $( [21-Nov-94] $)
  $}

  ${
    mp3an2.1 $e |- ps $.
    mp3an2.2 $e |- ( ( ph /\ ps /\ ch ) -> th ) $.
    $( An inference based on modus ponens. $)
    mp3an2 $p |- ( ( ph /\ ch ) -> th ) $=
      ( 3expa mpan12 ) ABCDEABCDFGH $.
      $( [21-Nov-94] $)
  $}

  ${
    mp3an3.1 $e |- ch $.
    mp3an3.2 $e |- ( ( ph /\ ps /\ ch ) -> th ) $.
    $( An inference based on modus ponens. $)
    mp3an3 $p |- ( ( ph /\ ps ) -> th ) $=
      ( wa 3expa mpan2 ) ABGCDEABCDFHI $.
      $( [21-Nov-94] $)
  $}

  ${
    mp3an11.1 $e |- ph $.
    mp3an11.2 $e |- ( ( ( ph /\ ps /\ ch ) /\ th ) -> ta ) $.
    $( An inference based on modus ponens. $)
    mp3an11 $p |- ( ( ( ps /\ ch ) /\ th ) -> ta ) $=
      ( wa wi w3a exp mp3an1 imp ) BCHDEABCDEIFABCJDEGKLM $.
      $( [25-Feb-05] $) $( [24-Feb-05] $)
  $}

  ${
    mp3an12.1 $e |- ps $.
    mp3an12.2 $e |- ( ( ( ph /\ ps /\ ch ) /\ th ) -> ta ) $.
    $( An inference based on modus ponens. $)
    mp3an12 $p |- ( ( ( ph /\ ch ) /\ th ) -> ta ) $=
      ( wa wi w3a exp mp3an2 imp ) ACHDEABCDEIFABCJDEGKLM $.
      $( [26-Feb-05] $) $( [24-Feb-05] $)
  $}

  ${
    mp3an13.1 $e |- ch $.
    mp3an13.2 $e |- ( ( ( ph /\ ps /\ ch ) /\ th ) -> ta ) $.
    $( An inference based on modus ponens. $)
    mp3an13 $p |- ( ( ( ph /\ ps ) /\ th ) -> ta ) $=
      ( wa wi w3a exp mp3an3 imp ) ABHDEABCDEIFABCJDEGKLM $.
      $( [25-Feb-05] $) $( [24-Feb-05] $)
  $}

  ${
    mp3an.1 $e |- ph $.
    mp3an.2 $e |- ps $.
    mp3an.3 $e |- ch $.
    mp3an.4 $e |- ( ( ph /\ ps /\ ch ) -> th ) $.
    $( An inference based on modus ponens. $)
    mp3an $p |- th $=
      ( mp3an1 mp2an ) BCDFGABCDEHIJ $.
      $( [14-May-99] $)
  $}

  ${
    ecased.1 $e |- ( ph -> ( ps \/ ch \/ th ) ) $.
    ecased.2 $e |- ( ph -> -. ch ) $.
    ecased.3 $e |- ( ph -> -. th ) $.
    $( Deduction for elimination by cases. $)
    ecased $p |- ( ph -> ps ) $=
      ( wo wn wa jca ioran sylibr w3o 3orass sylib ord mt3d ) ABCDHZACIZDIZJSIA
      TUAFGKCDLMABSABCDNBSHEBCDOPQR $.
      $( [22-Apr-94] $)
  $}


$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
      Other axiomatizations of classical propositional calculus
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( Carew Meredith's sole axiom for propositional calculus.  This amazing
     formula is thought to be the shortest possible single axiom for
     propositional calculus using negation, implication, and inference rule
     ~ ax-mp . Here we prove Meredith's axiom from ~ ax-1 , ~ ax-2 , and
     ~ ax-3 . Then from it we derive the Lukasiewicz axioms ~ luk-1 ,
     ~ luk-2 , and ~ luk-3 . Using these we finally re-derive our axioms as
     ~ ax1 , ~ ax2 , and ~ ax3 , thus proving the equivalence of all three
     systems.  C. A. Meredith, "Single Axioms for the Systems (C,N), (C,O)
     and (A,N) of the Two-Valued Propositional Calculus", _The Journal of
     Computing Systems_ vol. 3 (1953), pp. 155-164.  Meredith claimed to be
     close to a proof that this axiom is the shortest possible, but the proof
     was apparently never completed.

     An obscure Irish lecturer, Meredith (1904-1976) became enamored with
     logic somewhat late in life after attending talks by Lukasiewicz and
     produced many remarkable results such as this axiom.  From his obituary:
     "He did logic whenever time and opportunity presented themselves, and he
     did it on whatever materials came to hand:  in a pub, his favored pint
     of porter within reach, he would use the inside of cigarette packs to
     write proofs for logical colleagues."  $)

  meredith $p |- ( ( ( ( ( ph -> ps ) -> ( -. ch -> -. th ) ) -> ch ) ->
       ta ) -> ( ( ta -> ph ) -> ( th -> ph ) ) ) $=
    ( wi wn ax-3 pm2.21 syl4 com23 syl5 con3d pm2.27 impi com12 syl3d a2d con3
    syl6 syl ) ABFZCGZDGZFZFZCFZEFZEGZUCUCAGZUDFZFZGFZGZFZEAFZDAFZFUHUMEUMUGEUM
    ULCUFCULHUFUJUCUDUJUBUEABIJKLJMUOUPUKUQUOUJUIFUKUPUOUJUIUDUJUOUIUDFUJUNUDUI
    UNUJUDUCULUKUCUKNOPQPREASLADHTUA $.
    $( [14-Dec-02] $)

  $( Step 3 of Meredith's proof of Lukasiewicz axioms from his sole axiom.
     (The step numbers refer to Meredith's original paper.) $)
  merlem1 $p |- ( ( ( ch -> ( -. ph -> ps ) ) -> ta ) -> ( ph -> ta ) ) $=
    ( wn wi meredith ax-mp ) DAEZFIBFZEZIFFZJFCJFZFZMDFADFFJDECEFZEKEFZFOFDFLFN
    IBOKDGJPDCLGHDIJAMGH $.
    $( [14-Dec-02] $)

  $( Step 4 of Meredith's proof of Lukasiewicz axioms from his sole axiom. $)
  merlem2 $p |- ( ( ( ph -> ph ) -> ch ) -> ( th -> ch ) ) $=
    ( wi wn merlem1 meredith ax-mp ) BBDZAECEZDDADAADZDKBDCBDDAJIAFBBACKGH $.
    $( [14-Dec-02] $)

  $( Step 7 of Meredith's proof of Lukasiewicz axioms from his sole axiom. $)
  merlem3 $p |- ( ( ( ps -> ch ) -> ph ) -> ( ch -> ph ) ) $=
    ( wi wn merlem2 ax-mp meredith ) AADZCEZJDZDZCDBCDZDZMADCADZDOBEZPDDBDZLDZN
    KKDLDRJKIFKLQFGCABBLHGAACCMHG $.
    $( [14-Dec-02] $)

  $( Step 8 of Meredith's proof of Lukasiewicz axioms from his sole axiom. $)
  merlem4 $p |- ( ta -> ( ( ta -> ph ) -> ( th -> ph ) ) ) $=
    ( wi wn meredith merlem3 ax-mp ) AADBEZIDDBDZCDCADBADDZDCKDAABBCFKJCGH $.
    $( [14-Dec-02] $)

  $( Step 11 of Meredith's proof of Lukasiewicz axioms from his sole axiom. $)
  merlem5 $p |- ( ( ph -> ps ) -> ( -. -. ph -> ps ) ) $=
    ( wi wn meredith merlem1 merlem4 ax-mp ) BBCZBDZJCCBCBCIICCZABCZADZDZBCCZBB
    BBBEIJNDCCBCZACZOCZKOCZBBBNAEOKDZCMTCCZACQCZRSCUAUBMBLTFAPUAGHOTAKQEHHH $.
    $( [14-Dec-02] $)

  $( Step 12 of Meredith's proof of Lukasiewicz axioms from his sole axiom. $)
  merlem6 $p |- ( ch -> ( ( ( ps -> ch ) -> ph ) -> ( th -> ph ) ) ) $=
    ( wi merlem4 merlem3 ax-mp ) BCEZIAEDAEEZECJEADIFJBCGH $.
    $( [14-Dec-02] $)

  $( Between steps 14 and 15 of Meredith's proof of Lukasiewicz axioms from his
     sole axiom. $)
  merlem7 $p |- ( ph -> ( ( ( ps -> ch ) -> th ) -> ( ( ( ch -> ta ) ->
                  ( -. th -> -. ps ) ) -> th ) ) ) $=
    ( wi wn merlem4 merlem6 meredith ax-mp ) BCFZLDFZCEFDGBGFFZDFZFZFZAPFZDNLHP
    AGZFCGZSFFZCFLFZQRFOUAFUBSMOTICEDBUAJKPSCALJKK $.
    $( [22-Dec-02] $)

  $( Step 15 of Meredith's proof of Lukasiewicz axioms from his sole axiom. $)
  merlem8 $p |- ( ( ( ps -> ch ) -> th ) -> ( ( ( ch -> ta ) ->
                  ( -. th -> -. ps ) ) -> th ) ) $=
    ( wph wi wn meredith merlem7 ax-mp ) EEFZEGZLFFEFEFKKFFZABFCFBDFCGAGFFCFFEE
    EEEHMABCDIJ $.
    $( [22-Dec-02] $)

  ${
    $v et $. $( Greek eta $)
    meredith.we $f wff et $.
    $( Step 18 of Meredith's proof of Lukasiewicz axioms from his sole
       axiom. $)
    merlem9 $p |- ( ( ( ph -> ps ) -> ( ch -> ( th -> ( ps -> ta ) ) ) ) ->
                    ( et -> ( ch -> ( th -> ( ps -> ta ) ) ) ) ) $=
      ( wi wn merlem6 merlem8 ax-mp meredith ) CDBEGZGZGZFHZGBHZPGGZBGABGZGZSOG
      FOGGMRHDHGZHAHGZGUAGRGZTNRGUCPCNQIDMRUBJKBEUAARLKOPBFSLK $.
      $( [22-Dec-02] $)
  $}

  $( Step 19 of Meredith's proof of Lukasiewicz axioms from his sole axiom. $)
  merlem10 $p |- ( ( ph -> ( ph -> ps ) ) -> ( th -> ( ph -> ps ) ) ) $=
    ( wi wn meredith merlem9 ax-mp ) AADZAEZJDDADADIIDDZAABDZDZCLDDZAAAAAFLADJC
    EDDADZADNDKNDLAACAFOAMCBKGHH $.
    $( [14-Dec-02] $)

  $( Step 20 of Meredith's proof of Lukasiewicz axioms from his sole axiom. $)
  merlem11 $p |- ( ( ph -> ( ph -> ps ) ) -> ( ph -> ps ) ) $=
    ( wi wn meredith merlem10 ax-mp ) AACZADZICCACACHHCCZAABCZCZKCZAAAAAELMCJMC
    ABLFLKJFGG $.
    $( [14-Dec-02] $)

  $( Step 28 of Meredith's proof of Lukasiewicz axioms from his sole axiom. $)
  merlem12 $p |- ( ( ( th -> ( -. -. ch -> ch ) ) -> ph ) -> ph ) $=
    ( wn wi merlem5 merlem2 ax-mp merlem4 merlem11 ) CBDDBEZEZAEZMAEZEZNLOBBEKE
    LBBFBKCGHAMLIHMAJH $.
    $( [14-Dec-02] $)

  $( Step 35 of Meredith's proof of Lukasiewicz axioms from his sole axiom. $)
  merlem13 $p |- ( ( ph -> ps ) ->
              ( ( ( th -> ( -. -. ch -> ch ) ) -> -. -. ph ) -> ps ) ) $=
    ( wi wn merlem12 merlem5 ax-mp merlem6 meredith merlem11 ) BBEZAFZDCFFCEEZN
    FZEZFZEZEAEZAEZABEQBEETUAEZUASUBOREZREZSRCDGRBEZRFPEZEREUCEZUDSEUFUGQPEUFPC
    DGQPHIRUEUFOJIRBRNUCKIIAMSTJITALIBBAQAKI $.
    $( [14-Dec-02] $)

  $( 1 of 3 axioms for propositional calculus due to Lukasiewicz, derived from
     Meredith's sole axiom. $)
  luk-1 $p |- ( ( ph -> ps ) -> ( ( ps -> ch ) -> ( ph -> ch ) ) ) $=
    ( wi wn meredith merlem13 ax-mp ) CCDZAEZEZEJDDKDBDZBCDACDDZDZABDZMDZCCKABF
    MADZOEZEZERDDSDLDZNPDOLDTABJIGOLRQGHMASOLFHH $.
    $( [14-Dec-02] $)

  $( 2 of 3 axioms for propositional calculus due to Lukasiewicz, derived from
     Meredith's sole axiom. $)
  luk-2 $p |- ( ( -. ph -> ph ) -> ph ) $=
    ( wn wi merlem5 merlem4 ax-mp merlem11 meredith ) ABZACZJACZCZKAJBZCIBMCCZI
    CZICZLOPCZPNQAMDIONEFOIGFAMIJIHFJAGF $.
    $( [14-Dec-02] $)

  $( 3 of 3 axioms for propositional calculus due to Lukasiewicz, derived from
     Meredith's sole axiom. $)
  luk-3 $p |- ( ph -> ( -. ph -> ps ) ) $=
    ( wn wi merlem11 merlem1 ax-mp ) ACZHBDZDIDAIDHBEABHIFG $.
    $( [14-Dec-02] $)

  ${
    luklem1.1 $e |- ( ph -> ps ) $.
    luklem1.2 $e |- ( ps -> ch ) $.
    $( Lemma for rederiving standard propositional axioms from Lukasiewicz'. $)
    luklem1 $p |- ( ph -> ch ) $=
      ( wi luk-1 ax-mp ) BCFZACFZEABFIJFDABCGHH $.
      $( [23-Dec-02] $)
  $}

  $( Lemma for rederiving standard propositional axioms from Lukasiewicz'. $)
  luklem2 $p |- ( ( ph -> -. ps ) ->
                ( ( ( ph -> ch ) -> th ) -> ( ps -> th ) ) ) $=
    ( wn wi luk-1 luk-3 ax-mp luklem1 ) ABEZFZBACFZFZMDFBDFFLKCFZMFZNAKCGBOFPNF
    BCHBOMGIJBMDGJ $.
    $( [22-Dec-02] $)

  $( Lemma for rederiving standard propositional axioms from Lukasiewicz'. $)
  luklem3 $p |- ( ph -> ( ( ( -. ph -> ps ) -> ch ) -> ( th -> ch ) ) ) $=
    ( wn wi luk-3 luklem2 luklem1 ) AAEZDEZFJBFCFDCFFAKGJDBCHI $.
    $( [22-Dec-02] $)

  $( Lemma for rederiving standard propositional axioms from Lukasiewicz'. $)
  luklem4 $p |- ( ( ( ( -. ph -> ph ) -> ph ) -> ps ) -> ps ) $=
    ( wn wi luk-2 luklem3 ax-mp luk-1 luklem1 ) ACADADZBDZBCZBDZBLJDZKMDJCJDJDZ
    NJEJONDAEJJJLFGGLJBHGBEI $.
    $( [22-Dec-02] $)

  $( Lemma for rederiving standard propositional axioms from Lukasiewicz'. $)
  luklem5 $p |- ( ph -> ( ps -> ph ) ) $=
    ( wn wi luklem3 luklem4 luklem1 ) AACADADBADZDHAAABEAHFG $.
    $( [22-Dec-02] $)

  $( Lemma for rederiving standard propositional axioms from Lukasiewicz'. $)
  luklem6 $p |- ( ( ph -> ( ph -> ps ) ) -> ( ph -> ps ) ) $=
    ( wi luk-1 wn luklem5 luklem2 luklem4 luklem1 ax-mp ) AABCZCKBCZKCZKAKBDKEZ
    KCZKCMKCZCZPMOCZQNLCRNBEZNCZLNSFTSBCBCLCLSKBBGBLHIINLKDJMOKDJKPHJI $.
    $( [22-Dec-02] $)

  $( Lemma for rederiving standard propositional axioms from Lukasiewicz'. $)
  luklem7 $p |- ( ( ph -> ( ps -> ch ) ) -> ( ps -> ( ph -> ch ) ) ) $=
    ( wi luk-1 luklem5 luklem1 luklem6 ax-mp ) ABCDZDJCDZACDZDZBLDZAJCEBKDMNDBJ
    KDZKBJBDOBJFJBCEGJCHGBKLEIG $.
    $( [22-Dec-02] $)

  $( Lemma for rederiving standard propositional axioms from Lukasiewicz'. $)
  luklem8 $p |- ( ( ph -> ps ) -> ( ( ch -> ph ) -> ( ch -> ps ) ) ) $=
    ( wi luk-1 luklem7 ax-mp ) CADZABDZCBDZDDIHJDDCABEHIJFG $.
    $( [22-Dec-02] $)

  $( Standard propositional axiom derived from Lukasiewicz axioms. $)
  ax1 $p |- ( ph -> ( ps -> ph ) ) $=
    ( luklem5 ) ABC $.
    $( [22-Dec-02] $)

  $( Standard propositional axiom derived from Lukasiewicz axioms. $)
  ax2 $p |- ( ( ph -> ( ps -> ch ) ) -> ( ( ph -> ps ) -> ( ph -> ch ) ) ) $=
    ( wi luklem7 luklem8 luklem6 ax-mp luklem1 ) ABCDDBACDZDZABDZJDZABCEKLAJDZD
    ZMBJAFNJDOMDACGNJLFHII $.
    $( [22-Dec-02] $)

  $( Standard propositional axiom derived from Lukasiewicz axioms. $)
  ax3 $p |- ( ( -. ph -> -. ps ) -> ( ps -> ph ) ) $=
    ( wn wi luklem2 luklem4 luklem1 ) ACZBCDHADADBADZDIHBAAEAIFG $.
    $( [22-Dec-02] $)

$(
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
                             Predicate calculus
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
$)

$(
   Predicate calculus, or first-order logic, introduces quantifiers to make
   statements such as 'for all individuals, such-and-such is true' and 'there
   exist individuals such that... .'  We introduce a new kind of variable,
   called an 'individual variable,' that ranges over individuals.
   (Actually, in Metamath we are introducing 'metavariables' that range over
   the individual variables of textbook predicate calculus, but the theorems
   look the same.  This is a technical point you should be aware of when
   studying standard textbooks.)  In addition, predicate calculus introduces
   one or more 'predicate symbols' that combine individual variables to form
   wff's.  We will be concerned with two predicate symbols, the equality
   sign ` = ` used in all of mathematics and the stylized epsilon ` e. `
   used to express 'is an element of' in set theory.

   Our axioms look quite different from those in standard textbooks, but the
   rules for manipulating the symbols end up being considerably simpler.
   The axioms of standard textbooks are derived as theorems ~ stdpc4 and
   ~ stdpc5 .

   We will work with the axioms for predicate calculus in four phases.  Phase 1
   introduces pure predicate calculus, which has no predicate symbols.  Phase 2
   introduces the predicate symbol for equality.  Phase 3 introduces the
   stylized epsilon predicate symbol for set theory (without specifying any of
   its properties that are peculiar to set theory).  Phase 4 introduces the
   concept of distinct variables (our first use of the $d statement).

   After phase 3, we will define and develop the concept of
   substitution.  In standard textbooks, substitution is introduced immediately
   as a complex concept that is awkward to work with in a precise, mechanical
   way.  We will define it in terms of concepts contained in the
   axioms so that in principle it can be eliminated from the language
   entirely.

   Finally, we will define existential uniqueness and develop some basic facts
   about it.
$)

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        The axioms of pure predicate calculus
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( Declare new symbols needed for pure predicate calculus. $)
  $c A. $. $( 'inverted A' universal quantifier (read:  'for all') $)
  $c set $. $( Individual variable type (read:  'the following is an
             individual (set) variable' $)

  $( Declare some names for individual variables. $)
  $v x $.
  $v y $.
  $v z $.
  $v w $.
  $v v $.
  $v u $.
  $( Let ` x ` be an individual variable. $)
  vx $f set x $.
  $( Let ` y ` be an individual variable. $)
  vy $f set y $.
  $( Let ` z ` be an individual variable. $)
  vz $f set z $.
  $( Let ` w ` be an individual variable. $)
  vw $f set w $.
  $( Let ` v ` be an individual variable. $)
  vv $f set v $.
  $( Let ` u ` be an individual variable. $)
  vu $f set u $.

  $( Extend wff definition to include the universal quantifier ('for all').
     ` A. x ph ` is read " ` ph ` (phi) is true for all ` x ` ."  Typically,
     in its final application ` ph ` would be replaced with a wff containing
     a (free) occurrence of the variable ` x ` , for example ` x = y ` .
     In a universe with a finite number of objects, "for all" is equivalent
     to a big conjunction (AND) with one wff for each possible case of
     ` x ` .  When the universe is infinite (as with set theory), such a
     propositional-calculus equivalent is not possible because an infinitely
     long formula has no meaning, but conceptually the idea is the same. $)
  wal $a wff A. x ph $.

$(
   Postulate the four axioms of pure predicate calculus.  Note that these are
   valid even when ` x ` and ` y ` occur ('free' or not) in wff's ` ph `
   and ` ps ` .  Thus we do not have to worry about 'free' variable
   restrictions that complicate the traditional textbook axioms.
$)

  $( Axiom of Specialization.  A quantified wff implies the wff without a
     quantifier (i.e. an instance, or special case, of the generalized wff).
     In other words if something is true for all ` x ` , it is true for any
     specific ` x ` (that would typically occur as a free variable in the wff
     substituted for ` ph ` ). (A free variable is one that does not occur in
     the scope of a quantifier:  ` x ` and ` y ` are both free in
     ` x = y ` , but only ` y ` is free in ` A. x x = y ` .) This is one of
     the 4 axioms of what we call "pure" predicate calculus.  Unlike the more
     typical textbook Axiom of Specialization, we cannot choose a variable
     different from ` x ` for the special case.  That is dealt with later
     when substitution is introduced - see ~ stdpc4 . Axiom scheme C5' in
     [Megill] p. 448 (p. 16 of the preprint).  Also appears as Axiom B5 of
     [Tarski] p. 67 (under his system S2, defined in the last paragraph on
     p. 77).  Note that the converse of this axiom does not hold in general,
     but a weaker inference form of the converse holds and is expressed as
     rule ~ ax-gen . Conditional forms of the converse are given by ~ ax-12 ,
     ~ ax-15 , ~ ax-16 , and ~ ax-17 . $)
  ax-4 $a |- ( A. x ph -> ph ) $.

  $( Axiom of Quantified Implication.  This axiom moves a quantifier from
     outside to inside an implication, quantifying ` ps ` .  Notice that
     ` x ` must not be a free variable in the antecedent of the quantified
     implication, and we express this by binding ` ph ` to "protect" the
     axiom from a ` ph ` containing a free ` x ` .
     One of the 4 axioms of pure predicate calculus.  Axiom scheme C4' in
     [Megill] p. 448 (p. 16 of the preprint).  It is a special case of Lemma 5
     of [Monk2] p. 108. $)
  ax-5 $a |- ( A. x ( A. x ph -> ps ) -> ( A. x ph -> A. x ps ) ) $.

  $( Axiom of Quantified Negation.  This axiom is used to manipulate negated
     quantifiers.  One of the 4 axioms of pure predicate calculus.  Equivalent
     to axiom scheme C7' in [Megill] p. 448 (p. 16 of the preprint).  Another
     equivalent variant ~ ax6 appears as Axiom C5-2 of [Monk2] p. 113.  $)
  ax-6 $a |- ( -. A. x -. A. x ph -> ph ) $.

  $( Axiom of Quantifier Commutation.  This axiom says universal quantifiers
     can be swapped.  One of the 4 axioms of pure predicate calculus.  Axiom
     scheme C6' in [Megill] p. 448 (p. 16 of the preprint).  Also appears as
     Lemma 12 of [Monk2] p. 109. $)
  ax-7 $a |- ( A. x A. y ph -> A. y A. x ph ) $.

  ${
    ax-g.1 $e |- ph $.
    $( Rule of Generalization.  The postulated inference rule of pure predicate
       calculus.  See e.g. Rule 2 of [Hamilton] p. 74.  This rule says that if
       something is unconditionally true, then it is true for all values of a
       variable.  For example, if we have proved ` x = x ` , we can conclude
       ` A. x x = x ` or even ` A. y x = x ` .  Theorem ~ a4i shows we can go
      the other way also:  in other words we can add or remove universal
      quantifiers from the beginning of any theorem as required. $)
    ax-gen $a |- A. x ph $.
  $}


  $( Declare the existential quantifier symbol. $)
  $c E. $.    $( Backwards E (read:  'there exists') $)

  $( Extend wff definition to include the existential quantifier ("there
     exists"). $)
  wex $a wff E. x ph $.

  $( Define existential quantification.  ` E. x ph ` means "there exists at
     least one set ` x ` such that ` ph ` is true."  Definition of [Margaris]
     p. 49.  $)
  df-ex $a |- ( E. x ph <-> -. A. x -. ph ) $.

  ${
    a4i.1 $e |- A. x ph $.
    $( Inference rule reversing generalization. $)
    a4i $p |- ph $=
      ( wal ax-4 ax-mp ) ABDACABEF $.
      $( [5-Aug-93] $)
  $}

  ${
    gen2.1 $e |- ph $.
    $( Generalization applied twice. $)
    gen2 $p |- A. x A. y ph $=
      ( wal ax-gen ) ACEBACDFF $.
      $( [30-Apr-98] $)
  $}

  ${
    a4s.1 $e |- ( ph -> ps ) $.
    $( Generalization of antecedent. $)
    a4s $p |- ( A. x ph -> ps ) $=
      ( wal ax-4 syl ) ACEABACFDG $.
      $( [5-Aug-93] $)
  $}

  ${
    a4sd.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction generalizing antecedent. $)
    a4sd $p |- ( ph -> ( A. x ps -> ch ) ) $=
      ( wal ax-4 syl5 ) ABCBDFEBDGH $.
      $( [17-Aug-94] $)
  $}

  ${
    mpg.1 $e |- ( A. x ph -> ps ) $.
    mpg.2 $e |- ph $.
    $( Modus ponens combined with generalization. $)
    mpg $p |- ps $=
      ( wal ax-gen ax-mp ) ACFBACEGDH $.
      $( [24-May-94] $)
  $}

  ${
    mpgbi.1 $e |- ( A. x ph <-> ps ) $.
    mpgbi.2 $e |- ph $.
    $( Modus ponens on biconditional combined with generalization. $)
    mpgbi $p |- ps $=
      ( wal biimp mpg ) ABCACFBDGEH $.
      $( [24-May-94] $)
  $}

  ${
    mpgbir.1 $e |- ( ph <-> A. x ps ) $.
    mpgbir.2 $e |- ps $.
    $( Modus ponens on biconditional combined with generalization. $)
    mpgbir $p |- ph $=
      ( wal biimpr mpg ) BACABCFDGEH $.
      $( [24-May-94] $)
  $}

  ${
    a5i.1 $e |- ( A. x ph -> ps ) $.
    $( Inference from ~ ax-5 . $)
    a5i $p |- ( A. x ph -> A. x ps ) $=
      ( wal wi ax-5 mpg ) ACEZBFIBCEFCABCGDH $.
      $( [5-Aug-93] $)
  $}

  $( Abbreviated version of ~ ax-6 . $)
  a6e $p |- ( E. x A. x ph -> ph ) $=
    ( wal wex wn df-ex ax-6 sylbi ) ABCZBDIEBCEAIBFABGH $.
    $( [5-Aug-93] $)

  ${
    a7s.1 $e |- ( A. x A. y ph -> ps ) $.
    $( Swap quantifiers in an antecedent. $)
    a7s $p |- ( A. y A. x ph -> ps ) $=
      ( wal ax-7 syl ) ACFDFADFCFBADCGEH $.
      $( [5-Aug-93] $)
  $}

  $( Theorem 19.20 of [Margaris] p. 90. $)
  19.20 $p |- ( A. x ( ph -> ps ) -> ( A. x ph -> A. x ps ) ) $=
    ( wi wal ax-4 syl4 a4s a5i ax-5 syl ) ABDZCEACEZBDZCEMBCEDLNCLNCMABACFGHIAB
    CJK $.
    $( [5-Aug-93] $)

  ${
    19.20i.1 $e |- ( ph -> ps ) $.
    $( Inference quantifying both antecedent and consequent. $)
    19.20i $p |- ( A. x ph -> A. x ps ) $=
      ( a4s a5i ) ABCABCDEF $.
      $( [5-Aug-93] $)

    $( Inference doubly quantifying both antecedent and consequent. $)
    19.20i2 $p |- ( A. x A. y ph -> A. x A. y ps ) $=
      ( wal 19.20i ) ADFBDFCABDEGG $.
      $( [5-Feb-05] $) $( [3-Feb-05] $)
  $}

  ${
    19.20ii.1 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Inference quantifying antecedent, nested antecedent, and consequent. $)
    19.20ii $p |- ( A. x ph -> ( A. x ps -> A. x ch ) ) $=
      ( wal wi 19.20i 19.20 syl ) ADFBCGZDFBDFCDFGAKDEHBCDIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    19.20d.1 $e |- ( ph -> A. x ph ) $.
    19.20d.2 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction from Theorem 19.20 of [Margaris] p. 90. $)
    19.20d $p |- ( ph -> ( A. x ps -> A. x ch ) ) $=
      ( wal wi 19.20ii syl ) AADGBDGCDGHEABCDFIJ $.
      $( [4-Jan-02] $)
  $}

  $( Theorem 19.15 of [Margaris] p. 90. $)
  19.15 $p |- ( A. x ( ph <-> ps ) -> ( A. x ph <-> A. x ps ) ) $=
    ( wb wal bi1 19.20ii bi2 impbid ) ABDZCEACEBCEJABCABFGJBACABHGI $.
    $( [5-Aug-93] $)

  ${
    bial.1 $e |- ( ph <-> ps ) $.
    $( Inference adding universal quantifier to both sides of an
       equivalence. $)
    bial $p |- ( A. x ph <-> A. x ps ) $=
      ( wb wal 19.15 mpg ) ABEACFBCFECABCGDH $.
      $( [7-Aug-94] $)

    $( Inference adding 2 universal quantifiers to both sides of an
       equivalence. $)
    bi2al $p |- ( A. x A. y ph <-> A. x A. y ps ) $=
      ( wal bial ) ADFBDFCABDEGG $.
      $( [9-Mar-97] $)
  $}


  ${
    hbth.1 $e |- ph $.
    $( No variable is (effectively) free in a theorem.

       This and later "hypothesis-building" lemmas, with labels starting
       "hb...", allow us to construct proofs of formulas of the form
       ` |- ( ph -> A. x ph ) ` from smaller formulas of this form.  These are
       useful for constructing hypotheses that state
       " ` x ` is (effectively) not free in ` ph ` ". $)
    hbth $p |- ( ph -> A. x ph ) $=
      ( wal ax-gen a1i ) ABDAABCEF $.
      $( [5-Aug-93] $)
  $}

  $( ` x ` is not free in ` A. x ph ` .  Appendix example in [Megill] p. 450
     (p. 19 of the preprint). $)
  hba1 $p |- ( A. x ph -> A. x A. x ph ) $=
    ( wal id a5i ) AABCZBFDE $.
    $( [5-Aug-93] $)

  ${
    hb.1 $e |- ( ph -> A. x ph ) $.
    $( If ` x ` is not free in ` ph ` , it is not free in ` -. ph ` . $)
    hbne $p |- ( -. ph -> A. x -. ph ) $=
      ( wal wn con3i 19.20i ax-6 nsyl4 ) ABDZEZBDAEZBDAKLBAJCFGABHI $.
      $( [5-Aug-93] $)

    $( If ` x ` is not free in ` ph ` , it is not free in ` A. y ph ` . $)
    hbal $p |- ( A. y ph -> A. x A. y ph ) $=
      ( wal 19.20i ax-7 syl ) ACEZABEZCEIBEAJCDFACBGH $.
      $( [5-Aug-93] $)

    $( If ` x ` is not free in ` ph ` , it is not free in ` E. y ph ` . $)
    hbex $p |- ( E. y ph -> A. x E. y ph ) $=
      ( wn wal wex hbne hbal df-ex bial 3imtr4 ) AEZCFZEZOBFACGZPBFNBMBCABDHIHA
      CJZPOBQKL $.
      $( [5-Aug-93] $)
    ${

      hb.2 $e |- ( ps -> A. x ps ) $.
      $( If ` x ` is not free in ` ph ` and ` ps ` , it is not free in
         ` ( ph -> ps ) ` . $)
      hbim $p |- ( ( ph -> ps ) -> A. x ( ph -> ps ) ) $=
        ( wi wal wn hbne pm2.21 19.20i syl ax-1 ja ) ABABFZCGZAHZQCGPACDIQOCABJ
        KLBBCGPEBOCBAMKLN $.
        $( [5-Aug-93] $)

      $( If ` x ` is not free in ` ph ` and ` ps ` , it is not free in
         ` ( ph \/ ps ) ` . $)
      hbor $p |- ( ( ph \/ ps ) -> A. x ( ph \/ ps ) ) $=
        ( wn wi wal wo hbne hbim df-or bial 3imtr4 ) AFZBGZPCHABIZQCHOBCACDJEKA
        BLZQPCRMN $.
        $( [5-Aug-93] $)

      $( If ` x ` is not free in ` ph ` and ` ps ` , it is not free in
         ` ( ph /\ ps ) ` . $)
      hban $p |- ( ( ph /\ ps ) -> A. x ( ph /\ ps ) ) $=
        ( wn wi wal wa hbne hbim df-an bial 3imtr4 ) ABFZGZFZQCHABIZRCHPCAOCDBC
        EJKJABLZRQCSMN $.
        $( [5-Aug-93] $)

      $( If ` x ` is not free in ` ph ` and ` ps ` , it is not free in
         ` ( ph <-> ps ) ` . $)
      hbbi $p |- ( ( ph <-> ps ) -> A. x ( ph <-> ps ) ) $=
        ( wi wa wal wb hbim hban bi bial 3imtr4 ) ABFZBAFZGZQCHABIZRCHOPCABCDEJ
        BACEDJKABLZRQCSMN $.
        $( [5-Aug-93] $)

      ${

        hb.3 $e |- ( ch -> A. x ch ) $.
        $( If ` x ` is not free in ` ph ` , ` ps ` , and ` ch ` , it is not
           free in ` ( ph \/ ps \/ ch ) ` . $)
        hb3or $p |- ( ( ph \/ ps \/ ch ) -> A. x ( ph \/ ps \/ ch ) ) $=
          ( wo wal w3o hbor df-3or bial 3imtr4 ) ABHZCHZPDIABCJZQDIOCDABDEFKGKA
          BCLZQPDRMN $.
          $( [14-Sep-03] $)

        $( If ` x ` is not free in ` ph ` , ` ps ` , and ` ch ` , it is not
           free in ` ( ph /\ ps /\ ch ) ` . $)
        hb3an $p |- ( ( ph /\ ps /\ ch ) -> A. x ( ph /\ ps /\ ch ) ) $=
          ( wa wal w3a hban df-3an bial 3imtr4 ) ABHZCHZPDIABCJZQDIOCDABDEFKGKA
          BCLZQPDRMN $.
          $( [14-Sep-03] $)
      $}
    $}
  $}

  $( ` x ` is not free in ` -. A. x ph ` . $)
  hbn1 $p |- ( -. A. x ph -> A. x -. A. x ph ) $=
    ( wal hba1 hbne ) ABCBABDE $.
    $( [5-Aug-93] $)

  $( ` x ` is not free in ` E. x ph ` . $)
  hbe1 $p |- ( E. x ph -> A. x E. x ph ) $=
    ( wn wal wex hbn1 df-ex bial 3imtr4 ) ACZBDCZKBDABEZLBDJBFABGZLKBMHI $.
    $( [5-Aug-93] $)

  $( A closed form of hypothesis builder ~ hbne . $)
  hbnt $p |- ( A. x ( ph -> A. x ph ) -> ( -. ph -> A. x -. ph ) ) $=
    ( wal wi wn con3 19.20ii ax-6 con1i syl5 ) AABCZDZBCKEZBCZAEZBCOLMOBAKFGNAA
    BHIJ $.
    $( [5-Aug-93] $)

  $( Axiom C5-2 of [Monk2] p. 113, which we prove from our ~ ax-6 (and others).
     Conversely, ~ ax-6 follows from this using ~ ax-4 and propositional
     calculus, showing that they are interchangeable.   $)
  ax6 $p |- ( -. A. x ph -> A. x -. A. x ph ) $=
    ( hbn1 ) ABC $.
    $( [2-Dec-03] $) $( [2-Dec-03] $)

  $( If a wff is true, it is true for at least one instance. $)
  19.8a $p |- ( ph -> E. x ph ) $=
    ( wn wal wex ax-4 con2i df-ex sylibr ) AACZBDZCABEKAJBFGABHI $.
    $( [5-Aug-93] $)

  $( Theorem 19.2 of [Margaris] p. 89. $)
  19.2 $p |- ( A. x ph -> E. x ph ) $=
    ( wex 19.8a a4s ) AABCBABDE $.
    $( [5-Aug-93] $)

  ${
    19.3r.1 $e |- ( ph -> A. x ph ) $.
    $( A wff may be quantified with a variable not free in it. $)
    19.3r $p |- ( ph <-> A. x ph ) $=
      ( wal ax-4 impbi ) AABDCABEF $.
      $( [5-Aug-93] $)
  $}

  $( Theorem 19.5 of [Margaris] p. 89. $)
  alcom $p |- ( A. x A. y ph <-> A. y A. x ph ) $=
    ( wal ax-7 impbi ) ACDBDABDCDABCEACBEF $.
    $( [5-Aug-93] $)

  $( Theorem 19.7 of [Margaris] p. 89. $)
  alnex $p |- ( A. x -. ph <-> -. E. x ph ) $=
    ( wex wn wal df-ex bicon2i ) ABCADBEABFG $.
    $( [5-Aug-93] $)

  $( Theorem 19.6 of [Margaris] p. 89. $)
  alex $p |- ( A. x ph <-> -. E. x -. ph ) $=
    ( wal wn wex pm4.13 bial alnex bitr ) ABCADZDZBCJBEDAKBAFGJBHI $.
    $( [5-Aug-93] $)

  ${
    19.9r.1 $e |- ( ph -> A. x ph ) $.
    $( Variation of Theorem 19.9 of [Margaris] p. 89. $)
    19.9r $p |- ( ph <-> E. x ph ) $=
      ( wex 19.8a wn wal df-ex con3i 19.20i ax-6 syl sylbi impbi ) AABDZABEOAFZ
      BGZFZAABHRABGZFZBGZFAUAQTPBASCIJIABKLMN $.
      $( [5-Aug-93] $)
  $}

  $( A closed version of one direction of ~ 19.9r . $)
  19.9t $p |- ( A. x ( ph -> A. x ph ) -> ( E. x ph -> ph ) ) $=
    ( wal wi wn wex hbnt con1d df-ex syl5ib ) AABCDBCZAEBCZEAABFKALABGHABIJ $.
    $( [5-Aug-93] $)

  ${
    19.9d.1 $e |- ( ps -> A. x ps ) $.
    19.9d.2 $e |- ( ps -> ( ph -> A. x ph ) ) $.
    $( A deduction version of one direction of ~ 19.9r . $)
    19.9d $p |- ( ps -> ( E. x ph -> ph ) ) $=
      ( wal wi wex 19.20i 19.9t 3syl ) BBCFAACFGZCFACHAGDBLCEIACJK $.
      $( [5-Aug-93] $)
  $}

  $( Theorem 19.14 of [Margaris] p. 90. $)
  exnal $p |- ( E. x -. ph <-> -. A. x ph ) $=
    ( wal wn wex alex bicon2i ) ABCADBEABFG $.
    $( [5-Aug-93] $)

  $( Theorem 19.22 of [Margaris] p. 90. $)
  19.22 $p |- ( A. x ( ph -> ps ) -> ( E. x ph -> E. x ps ) ) $=
    ( wi wal wn wex con3 19.20ii con3d df-ex 3imtr4g ) ABDZCEZAFZCEZFBFZCEZFACG
    BCGNRPMQOCABHIJACKBCKL $.
    $( [5-Aug-93] $)

  ${
    19.22i.1 $e |- ( ph -> ps ) $.
    $( Inference adding existential quantifier to antecedent and consequent. $)
    19.22i $p |- ( E. x ph -> E. x ps ) $=
      ( wi wex 19.22 mpg ) ABEACFBCFECABCGDH $.
      $( [5-Aug-93] $)

    $( Inference adding 2 existential quantifiers to antecedent and
       consequent. $)
    19.22i2 $p |- ( E. x E. y ph -> E. x E. y ps ) $=
      ( wex 19.22i ) ADFBDFCABDEGG $.
      $( [5-Feb-05] $) $( [3-Feb-05] $)
  $}

  $( A transformation of quantifiers and logical connectives. $)
  alinexa $p |- ( A. x ( ph -> -. ps ) <-> -. E. x ( ph /\ ps ) ) $=
    ( wn wi wal wa wex imnan bial alnex bitr ) ABDEZCFABGZDZCFNCHDMOCABIJNCKL
    $.
    $( [19-Aug-93] $)

  $( A transformation of quantifiers and logical connectives. $)
  exanali $p |- ( E. x ( ph /\ -. ps ) <-> -. A. x ( ph -> ps ) ) $=
    ( wi wal wn wa wex iman bial alnex bitr bicon2i ) ABDZCEZABFGZCHZOPFZCEQFNR
    CABIJPCKLM $.
    $( [25-Mar-96] $)

  $( A relationship between two quantifiers and negation. $)
  alexn $p |- ( A. x E. y -. ph <-> -. E. x A. y ph ) $=
    ( wn wex wal exnal bial alnex bitr ) ADCEZBFACFZDZBFLBEDKMBACGHLBIJ $.
    $( [18-Aug-93] $)

  $( One direction of Theorem 19.11 of [Margaris] p. 89. $)
  excomim $p |- ( E. x E. y ph -> E. y E. x ph ) $=
    ( wex 19.8a 19.22i2 hbe1 hbex 19.9r sylibr ) ACDBDABDZCDZBDLAKBCABEFLBKBCAB
    GHIJ $.
    $( [5-Aug-93] $)

  $( Theorem 19.11 of [Margaris] p. 89. $)
  excom $p |- ( E. x E. y ph <-> E. y E. x ph ) $=
    ( wex excomim impbi ) ACDBDABDCDABCEACBEF $.
    $( [5-Aug-93] $)

  $( Theorem 19.12 of [Margaris] p. 89. Assuming the converse is a mistake
     sometimes made by beginners!   But sometimes the converse does hold,
     as in ~ 19.12vv . $)
  19.12 $p |- ( E. x A. y ph -> A. y E. x ph ) $=
    ( wal wex hba1 hbex ax-4 19.22i 19.20i syl ) ACDZBEZMCDABEZCDLCBACFGMNCLABA
    CHIJK $.
    $( [5-Aug-93] $)

  ${
    19.16.1 $e |- ( ph -> A. x ph ) $.
    $( Theorem 19.16 of [Margaris] p. 90. $)
    19.16 $p |- ( A. x ( ph <-> ps ) -> ( ph <-> A. x ps ) ) $=
      ( wb wal 19.15 19.3r syl5bb ) ABECFACFBCFAABCGACDHI $.
      $( [5-Aug-93] $)
  $}

  ${
    19.17.1 $e |- ( ps -> A. x ps ) $.
    $( Theorem 19.17 of [Margaris] p. 90. $)
    19.17 $p |- ( A. x ( ph <-> ps ) -> ( A. x ph <-> ps ) ) $=
      ( wb wal 19.15 19.3r syl6bbr ) ABECFACFBCFBABCGBCDHI $.
      $( [5-Aug-93] $)
  $}

  $( Theorem 19.18 of [Margaris] p. 90. $)
  19.18 $p |- ( A. x ( ph <-> ps ) -> ( E. x ph <-> E. x ps ) ) $=
    ( wb wal wex wi bi1 19.20i 19.22 syl bi2 impbid ) ABDZCEZACFZBCFZOABGZCEPQG
    NRCABHIABCJKOBAGZCEQPGNSCABLIBACJKM $.
    $( [5-Aug-93] $)

  ${
    biex.1 $e |- ( ph <-> ps ) $.
    $( Inference adding existential quantifier to both sides of an
       equivalence. $)
    biex $p |- ( E. x ph <-> E. x ps ) $=
      ( wb wex 19.18 mpg ) ABEACFBCFECABCGDH $.
      $( [24-May-94] $)
  $}

  ${
    bi2ex.1 $e |- ( ph <-> ps ) $.
    $( Inference adding 2 existential quantifiers to both sides of an
       equivalence. $)
    bi2ex $p |- ( E. x E. y ph <-> E. x E. y ps ) $=
      ( wex biex ) ADFBDFCABDEGG $.
      $( [16-Mar-95] $)
  $}

  ${
    bi3ex.1 $e |- ( ph <-> ps ) $.
    $( Inference adding 3 existential quantifiers to both sides of an
       equivalence. $)
    bi3ex $p |- ( E. x E. y E. z ph <-> E. x E. y E. z ps ) $=
      ( wex biex bi2ex ) AEGBEGCDABEFHI $.
      $( [2-May-95] $)
  $}

  $( Commutation of conjunction inside an existential quantifier. $)
  exancom $p |- ( E. x ( ph /\ ps ) <-> E. x ( ps /\ ph ) ) $=
    ( wa ancom biex ) ABDBADCABEF $.
    $( [18-Aug-93] $)

  ${
    19.19.1 $e |- ( ph -> A. x ph ) $.
    $( Theorem 19.19 of [Margaris] p. 90. $)
    19.19 $p |- ( A. x ( ph <-> ps ) -> ( ph <-> E. x ps ) ) $=
      ( wb wal wex 19.18 19.9r syl5bb ) ABECFACGBCGAABCHACDIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    19.21.1 $e |- ( ph -> A. x ph ) $.
    $( Theorem 19.21 of [Margaris] p. 90.  The hypothesis can be thought of as
       " ` x ` is not free in ` ph ` ". $)
    19.21 $p |- ( A. x ( ph -> ps ) <-> ( ph -> A. x ps ) ) $=
      ( wi wal 19.20 syl5 hba1 hbim ax-4 syl3 19.20i syl impbi ) ABEZCFZABCFZEZ
      QACFRAABCGDHSSCFQARCDBCIJSPCRBABCKLMNO $.
      $( [5-Aug-93] $)
  $}

  ${
    19.21-2.1 $e |- ( ph -> A. x ph ) $.
    19.21-2.2 $e |- ( ph -> A. y ph ) $.
    $( Theorem 19.21 of [Margaris] p. 90 but with 2 quantifiers. $)
    19.21-2 $p |- ( A. x A. y ( ph -> ps ) <-> ( ph -> A. x A. y ps ) ) $=
      ( wi wal 19.21 bial bitr ) ABGDHZCHABDHZGZCHAMCHGLNCABDFIJAMCEIK $.
      $( [11-Feb-05] $) $( [4-Feb-05] $)
  $}

  ${
    stdpc5.1 $e |- ( ph -> A. x ph ) $.
    $( An axiom of standard predicate calculus.  Axiom 5 of [Mendelson] p. 69.
       The hypothesis ` ( ph -> A. x ph ) ` can be thought of as " ` x ` is not
       free in ` ph ` ".  With this convention, the meaning of "not free" is
       less restrictive than the usual textbook definition; for example ` x `
       would not (for us) be free in ` x = x ` by ~ hbequid . $)
    stdpc5 $p |- ( A. x ( ph -> ps ) -> ( ph -> A. x ps ) ) $=
      ( wi wal 19.21 biimp ) ABECFABCFEABCDGH $.
      $( [22-Sep-93] $)
  $}

  ${
    19.21ai.1 $e |- ( ph -> A. x ph ) $.
    19.21ai.2 $e |- ( ph -> ps ) $.
    $( Inference from Theorem 19.21 of [Margaris] p. 90. $)
    19.21ai $p |- ( ph -> A. x ps ) $=
      ( wal 19.20i syl ) AACFBCFDABCEGH $.
      $( [5-Aug-93] $)
  $}

  ${
    19.21ad.1 $e |- ( ph -> A. x ph ) $.
    19.21ad.2 $e |- ( ps -> A. x ps ) $.
    19.21ad.3 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction from Theorem 19.21 of [Margaris] p. 90. $)
    19.21ad $p |- ( ph -> ( ps -> A. x ch ) ) $=
      ( wal wa hban imp 19.21ai exp ) ABCDHABICDABDEFJABCGKLM $.
      $( [10-Feb-97] $)
  $}

  ${
    19.21bi.1 $e |- ( ph -> A. x ps ) $.
    $( Inference from Theorem 19.21 of [Margaris] p. 90. $)
    19.21bi $p |- ( ph -> ps ) $=
      ( wal ax-4 syl ) ABCEBDBCFG $.
      $( [5-Aug-93] $)
  $}

  ${
    19.21bbi.1 $e |- ( ph -> A. x A. y ps ) $.
    $( Inference removing double quantifier. $)
    19.21bbi $p |- ( ph -> ps ) $=
      ( wal 19.21bi ) ABDABDFCEGG $.
      $( [20-Apr-94] $)
  $}

  ${
    19.22d.1 $e |- ( ph -> A. x ph ) $.
    19.22d.2 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction from Theorem 19.22 of [Margaris] p. 90. $)
    19.22d $p |- ( ph -> ( E. x ps -> E. x ch ) ) $=
      ( wi wal wex 19.21ai 19.22 syl ) ABCGZDHBDICDIGAMDEFJBCDKL $.
      $( [20-May-96] $)
  $}

  ${
    19.23.1 $e |- ( ps -> A. x ps ) $.
    $( Theorem 19.23 of [Margaris] p. 90. $)
    19.23 $p |- ( A. x ( ph -> ps ) <-> ( E. x ph -> ps ) ) $=
      ( wi wal wex 19.22 19.9r syl6ibr hbe1 hbim 19.8a syl4 19.21ai impbi ) ABE
      ZCFZACGZBEZRSBCGBABCHBCDIJTQCSBCACKDLASBACMNOP $.
      $( [5-Aug-93] $)
  $}

  ${
    19.23ai.1 $e |- ( ps -> A. x ps ) $.
    19.23ai.2 $e |- ( ph -> ps ) $.
    $( Inference from Theorem 19.23 of [Margaris] p. 90. $)
    19.23ai $p |- ( E. x ph -> ps ) $=
      ( wex 19.22i 19.9r sylibr ) ACFBCFBABCEGBCDHI $.
      $( [5-Aug-93] $)
  $}

  ${
    19.23bi.1 $e |- ( E. x ph -> ps ) $.
    $( Inference from Theorem 19.23 of [Margaris] p. 90. $)
    19.23bi $p |- ( ph -> ps ) $=
      ( wex 19.8a syl ) AACEBACFDG $.
      $( [5-Aug-93] $)
  $}

  ${
    19.23ad.1 $e |- ( ph -> A. x ph ) $.
    19.23ad.2 $e |- ( ch -> A. x ch ) $.
    19.23ad.3 $e |- ( ph -> ( ps -> ch ) ) $.
    $( Deduction from Theorem 19.23 of [Margaris] p. 90. $)
    19.23ad $p |- ( ph -> ( E. x ps -> ch ) ) $=
      ( wi wal wex 19.21ai 19.23 sylib ) ABCHZDIBDJCHANDEGKBCDFLM $.
      $( [28-Jan-97] $)
  $}

  $( Theorem 19.26 of [Margaris] p. 90. $)
  19.26 $p |- ( A. x ( ph /\ ps ) <-> ( A. x ph /\ A. x ps ) ) $=
    ( wa wal pm3.26 19.20i pm3.27 jca pm3.2 19.20ii imp impbi ) ABDZCEZACEZBCEZ
    DOPQNACABFGNBCABHGIPQOABNCABJKLM $.
    $( [5-Aug-93] $)


  ${
    19.27.1 $e |- ( ps -> A. x ps ) $.
    $( Theorem 19.27 of [Margaris] p. 90. $)
    19.27 $p |- ( A. x ( ph /\ ps ) <-> ( A. x ph /\ ps ) ) $=
      ( wa wal 19.26 19.3r anbi2i bitr4 ) ABECFACFZBCFZEKBEABCGBLKBCDHIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    19.28.1 $e |- ( ph -> A. x ph ) $.
    $( Theorem 19.28 of [Margaris] p. 90. $)
    19.28 $p |- ( A. x ( ph /\ ps ) <-> ( ph /\ A. x ps ) ) $=
      ( wa wal 19.26 19.3r anbi1i bitr4 ) ABECFACFZBCFZEALEABCGAKLACDHIJ $.
      $( [5-Aug-93] $)
  $}

  $( Theorem 19.29 of [Margaris] p. 90. $)
  19.29 $p |- ( ( A. x ph /\ E. x ps ) -> E. x ( ph /\ ps ) ) $=
    ( wal wex wa wn wi 19.20 alnex syl6ib con3i df-an exnal 3imtr4 biex sylibr
    ) ACDZBCEZFZABGZHZGZCEZABFZCERSGZHZGUBCDZGTUDUHUGUHRUACDUFAUACIBCJKLRSMUBCN
    OUEUCCABMPQ $.
    $( [5-Aug-93] $)

  $( Variation of Theorem 19.29 of [Margaris] p. 90. $)
  19.29r $p |- ( ( E. x ph /\ A. x ps ) -> E. x ( ph /\ ps ) ) $=
    ( wal wex wa 19.29 ancom exancom 3imtr4 ) BCDZACEZFBAFCELKFABFCEBACGLKHABCI
    J $.
    $( [18-Aug-93] $)

  $( Variation of Theorem 19.29 of [Margaris] p. 90 with double
     quantification. $)
  19.29r2 $p |- ( ( E. x E. y ph /\ A. x A. y ps ) ->
             E. x E. y ( ph /\ ps ) ) $=
    ( wex wal wa 19.29r 19.22i syl ) ADEZCEBDFZCFGKLGZCEABGDEZCEKLCHMNCABDHIJ
    $.
    $( [11-Feb-05] $) $( [3-Feb-05] $)

  $( Variation of Theorem 19.29 of [Margaris] p. 90 with mixed
     quantification. $)
  19.29x $p |- ( ( E. x A. y ph /\ A. x E. y ps ) ->
             E. x E. y ( ph /\ ps ) ) $=
    ( wal wex wa 19.29r 19.29 19.22i syl ) ADEZCFBDFZCEGLMGZCFABGDFZCFLMCHNOCAB
    DIJK $.
    $( [25-Mar-05] $) $( [11-Feb-05] $)

  $( Theorem 19.35 of [Margaris] p. 90.  This theorem is useful for moving
     an implication (in the form of the right-hand side) into the scope of a
     single existential quantifier.  $)
  19.35 $p |- ( E. x ( ph -> ps ) <-> ( A. x ph -> E. x ps ) ) $=
    ( wal wn wi wex wa 19.26 annim bial df-an 3bitr3 bicon2i df-ex imbi2i
    3bitr4r ) ACDZBEZCDZEZFZABFZEZCDZERBCGZFUCCGUEUBASHZCDRTHUEUBEASCIUGUDCABJK
    RTLMNUFUARBCOPUCCOQ $.
    $( [5-Aug-93] $)

  ${
    19.35i.1 $e |- E. x ( ph -> ps ) $.
    $( Inference from Theorem 19.35 of [Margaris] p. 90. $)
    19.35i $p |- ( A. x ph -> E. x ps ) $=
      ( wi wex wal 19.35 mpbi ) ABECFACGBCFEDABCHI $.
      $( [5-Aug-93] $)
  $}

  ${
    19.35ri.1 $e |- ( A. x ph -> E. x ps ) $.
    $( Inference from Theorem 19.35 of [Margaris] p. 90. $)
    19.35ri $p |- E. x ( ph -> ps ) $=
      ( wi wex wal 19.35 mpbir ) ABECFACGBCFEDABCHI $.
      $( [5-Aug-93] $)
  $}

  ${
    19.36.1 $e |- ( ps -> A. x ps ) $.
    $( Theorem 19.36 of [Margaris] p. 90. $)
    19.36 $p |- ( E. x ( ph -> ps ) <-> ( A. x ph -> ps ) ) $=
      ( wi wex wal 19.35 19.9r imbi2i bitr4 ) ABECFACGZBCFZELBEABCHBMLBCDIJK $.
      $( [5-Aug-93] $)
  $}

  ${
    19.36i.1 $e |- ( ps -> A. x ps ) $.
    19.36i.2 $e |- E. x ( ph -> ps ) $.
    $( Inference from Theorem 19.36 of [Margaris] p. 90. $)
    19.36i $p |- ( A. x ph -> ps ) $=
      ( wi wex wal 19.36 mpbi ) ABFCGACHBFEABCDIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    19.37.1 $e |- ( ph -> A. x ph ) $.
    $( Theorem 19.37 of [Margaris] p. 90. $)
    19.37 $p |- ( E. x ( ph -> ps ) <-> ( ph -> E. x ps ) ) $=
      ( wi wex wal 19.35 19.3r imbi1i bitr4 ) ABECFACGZBCFZEAMEABCHALMACDIJK $.
      $( [5-Aug-93] $)
  $}

  $( Theorem 19.38 of [Margaris] p. 90. $)
  19.38 $p |- ( ( E. x ph -> A. x ps ) -> A. x ( ph -> ps ) ) $=
    ( wex wal wi hbe1 hba1 hbim 19.8a ax-4 syl34 19.21ai ) ACDZBCEZFABFCNOCACGB
    CHIANOBACJBCKLM $.
    $( [5-Aug-93] $)

  $( Theorem 19.39 of [Margaris] p. 90. $)
  19.39 $p |- ( ( E. x ph -> E. x ps ) -> E. x ( ph -> ps ) ) $=
    ( wex wi wal 19.2 syl4 19.35 sylibr ) ACDZBCDZEACFZLEABECDMKLACGHABCIJ $.
    $( [5-Aug-93] $)

  $( Theorem 19.24 of [Margaris] p. 90. $)
  19.24 $p |- ( ( A. x ph -> A. x ps ) -> E. x ( ph -> ps ) ) $=
    ( wal wi wex 19.2 syl3 19.35 sylibr ) ACDZBCDZEKBCFZEABECFLMKBCGHABCIJ $.
    $( [5-Aug-93] $)

  $( Theorem 19.25 of [Margaris] p. 90. $)
  19.25 $p |- ( A. y E. x ( ph -> ps ) ->
              ( E. y A. x ph -> E. y E. x ps ) ) $=
    ( wi wex wal 19.35 biimp 19.20i 19.22 syl ) ABECFZDGACGZBCFZEZDGNDFODFEMPDM
    PABCHIJNODKL $.
    $( [5-Aug-93] $)

  $( Theorem 19.30 of [Margaris] p. 90. $)
  19.30 $p |- ( A. x ( ph \/ ps ) -> ( A. x ph \/ E. x ps ) ) $=
    ( wn wi wal wo wex 19.20 orcom df-or bitr bial df-ex orbi2i imor 3bitr4
    3imtr4 ) BDZAEZCFSCFZACFZEZABGZCFUBBCHZGZSACIUDTCUDBAGTABJBAKLMUBUADZGUGUBG
    UFUCUBUGJUEUGUBBCNOUAUBPQR $.
    $( [5-Aug-93] $)

  ${
    19.32.1 $e |- ( ph -> A. x ph ) $.
    $( Theorem 19.32 of [Margaris] p. 90. $)
    19.32 $p |- ( A. x ( ph \/ ps ) <-> ( ph \/ A. x ps ) ) $=
      ( wn wi wal wo hbne 19.21 df-or bial 3bitr4 ) AEZBFZCGNBCGZFABHZCGAPHNBCA
      CDIJQOCABKLAPKM $.
      $( [5-Aug-93] $)
  $}

  ${
    19.31.1 $e |- ( ps -> A. x ps ) $.
    $( Theorem 19.31 of [Margaris] p. 90. $)
    19.31 $p |- ( A. x ( ph \/ ps ) <-> ( A. x ph \/ ps ) ) $=
      ( wo wal 19.32 orcom bial 3bitr4 ) BAEZCFBACFZEABEZCFLBEBACDGMKCABHILBHJ
      $.
      $( [5-Aug-93] $)
  $}

  $( Theorem 19.43 of [Margaris] p. 90. $)
  19.43 $p |- ( E. x ( ph \/ ps ) <-> ( E. x ph \/ E. x ps ) ) $=
    ( wo wn wal wex wa ioran bial 19.26 alnex anbi12i 3bitr negbii df-ex oran
    3bitr4 ) ABDZEZCFZEACGZEZBCGZEZHZESCGUBUDDUAUFUAAEZBEZHZCFUGCFZUHCFZHUFTUIC
    ABIJUGUHCKUJUCUKUEACLBCLMNOSCPUBUDQR $.
    $( [5-Aug-93] $)

  ${
    19.44.1 $e |- ( ps -> A. x ps ) $.
    $( Theorem 19.44 of [Margaris] p. 90. $)
    19.44 $p |- ( E. x ( ph \/ ps ) <-> ( E. x ph \/ ps ) ) $=
      ( wo wex 19.43 19.9r orbi2i bitr4 ) ABECFACFZBCFZEKBEABCGBLKBCDHIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    19.45.1 $e |- ( ph -> A. x ph ) $.
    $( Theorem 19.45 of [Margaris] p. 90. $)
    19.45 $p |- ( E. x ( ph \/ ps ) <-> ( ph \/ E. x ps ) ) $=
      ( wo wex 19.43 19.9r orbi1i bitr4 ) ABECFACFZBCFZEALEABCGAKLACDHIJ $.
      $( [5-Aug-93] $)
  $}

  $( Theorem 19.33 of [Margaris] p. 90. $)
  19.33 $p |- ( ( A. x ph \/ A. x ps ) -> A. x ( ph \/ ps ) ) $=
    ( wal wo orc 19.20i olc jaoi ) ACDABEZCDBCDAJCABFGBJCBAHGI $.
    $( [5-Aug-93] $)

  $( The antecedent provides a condition implying the converse of ~ 19.33 .
     Compare Theorem 19.33 of [Margaris] p. 90. $)
  19.33b $p |- ( -. ( E. x ph /\ E. x ps ) ->
               (  A. x ( ph \/ ps ) <-> ( A. x ph \/ A. x ps ) ) ) $=
    ( wex wa wn wo wal wi ianor alnex orbi12i bitr4 wb biorf 19.20i 19.15 syl
    olc syl6bir orcom syl6bb orc jaoi sylbi 19.33 a1i impbid ) ACDZBCDZEFZABGZC
    HZACHZBCHZGZUKAFZCHZBFZCHZGZUMUPIZUKUIFZUJFZGVAUIUJJURVCUTVDACKBCKLMURVBUTU
    RUMUOUPURBULNZCHUOUMNUQVECABOPBULCQRUOUNSTUTUMUNUPUTAULNZCHUNUMNUSVFCUSABAG
    ULBAOBAUAUBPAULCQRUNUOUCTUDUEUPUMIUKABCUFUGUH $.
    $( [2-Apr-04] $) $( [27-Mar-04] $)

  $( Theorem 19.34 of [Margaris] p. 90. $)
  19.34 $p |- ( ( A. x ph \/ E. x ps ) -> E. x ( ph \/ ps ) ) $=
    ( wal wex wo 19.2 orim1i 19.43 sylibr ) ACDZBCEZFACEZLFABFCEKMLACGHABCIJ $.
    $( [5-Aug-93] $)

  $( Theorem 19.40 of [Margaris] p. 90. $)
  19.40 $p |- ( E. x ( ph /\ ps ) -> ( E. x ph /\ E. x ps ) ) $=
    ( wa wex pm3.26 19.22i pm3.27 jca ) ABDZCEACEBCEJACABFGJBCABHGI $.
    $( [5-Aug-93] $)

  ${
    19.41.1 $e |- ( ps -> A. x ps ) $.
    $( Theorem 19.41 of [Margaris] p. 90. $)
    19.41 $p |- ( E. x ( ph /\ ps ) <-> ( E. x ph /\ ps ) ) $=
      ( wa wex wn wal df-ex wo hbne 19.31 ianor bial alnex orbi1i bitr4 3bitr4
      bicon2i ) ABEZCFTGZCHZGACFZBEZTCIUBUDAGZBGZJZCHUECHZUFJZUBUDGZUEUFCBCDKLU
      AUGCABMNUJUCGZUFJUIUCBMUHUKUFACOPQRSQ $.
      $( [5-Aug-93] $)
  $}

  ${
    19.42.1 $e |- ( ph -> A. x ph ) $.
    $( Theorem 19.42 of [Margaris] p. 90. $)
    19.42 $p |- ( E. x ( ph /\ ps ) <-> ( ph /\ E. x ps ) ) $=
      ( wa wex 19.41 exancom ancom 3bitr4 ) BAECFBCFZAEABECFAKEBACDGABCHAKIJ $.
      $( [18-Aug-93] $)
  $}

  $( Rotate 4 universal quantifiers twice. $)
  alrot4 $p |- ( A. x A. y A. z A. w ph <-> A. z A. w A. x A. y ph ) $=
    ( wal alcom bial bitr 3bitr ) AEFZDFCFZBFACFZEFZDFZBFNBFZDFMBFEFZDFLOBLKCFZ
    DFOKCDGRNDACEGHIHNBDGPQDMBEGHJ $.
    $( [7-Feb-05] $) $( [2-Feb-05] $)

  $( Swap 1st and 3rd existential quantifiers. $)
  excom13 $p |- ( E. x E. y E. z ph <-> E. z E. y E. x ph ) $=
    ( wex excom biex 3bitr ) ADEZCEBEIBEZCEABEZDEZCEKCEDEIBCFJLCABDFGKCDFH $.
    $( [9-Mar-95] $)

  $( Rotate existential quantifiers. $)
  exrot3 $p |- ( E. x E. y E. z ph <-> E. y E. z E. x ph ) $=
    ( wex excom13 excom bitr ) ADECEBEABEZCEDEIDECEABCDFIDCGH $.
    $( [17-Mar-95] $)

  $( Rotate existential quantifiers twice. $)
  exrot4 $p |- ( E. x E. y E. z E. w ph <-> E. z E. w E. x E. y ph ) $=
    ( wex excom13 biex bitr ) AEFDFCFZBFACFZDFEFZBFKBFEFDFJLBACDEGHKBEDGI $.
    $( [9-Mar-95] $)

  ${
    nex.1 $e |- -. ph $.
    $( Generalization rule for negated wff. $)
    nex $p |- -. E. x ph $=
      ( wn wex alnex mpgbi ) ADABEDBABFCG $.
      $( [18-May-94] $)
  $}

  ${
    nexd.1 $e |- ( ph -> A. x ph ) $.
    nexd.2 $e |- ( ph -> -. ps ) $.
    $( Deduction for generalization rule for negated wff. $)
    nexd $p |- ( ph -> -. E. x ps ) $=
      ( wn wal wex 19.21ai alnex sylib ) ABFZCGBCHFALCDEIBCJK $.
      $( [2-Jan-02] $)
  $}

  ${
    hbim1.1 $e |- ( ph -> A. x ph ) $.
    hbim1.2 $e |- ( ph -> ( ps -> A. x ps ) ) $.
    $( A closed form of ~ hbim . $)
    hbim1 $p |- ( ( ph -> ps ) -> A. x ( ph -> ps ) ) $=
      ( wi wal a2i 19.21 sylibr ) ABFZABCGZFKCGABLEHABCDIJ $.
      $( [5-Aug-93] $)
  $}

  ${
    biald.1 $e |- ( ph -> A. x ph ) $.
    biald.2 $e |- ( ph -> ( ps <-> ch ) ) $.
    $( Formula-building rule for universal quantifier (deduction rule). $)
    biald $p |- ( ph -> ( A. x ps <-> A. x ch ) ) $=
      ( wb wal 19.21ai 19.15 syl ) ABCGZDHBDHCDHGALDEFIBCDJK $.
      $( [5-Aug-93] $)
  $}

  ${
    biexd.1 $e |- ( ph -> A. x ph ) $.
    biexd.2 $e |- ( ph -> ( ps <-> ch ) ) $.
    $( Formula-building rule for existential quantifier (deduction rule). $)
    biexd $p |- ( ph -> ( E. x ps <-> E. x ch ) ) $=
      ( wb wal wex 19.21ai 19.18 syl ) ABCGZDHBDICDIGAMDEFJBCDKL $.
      $( [5-Aug-93] $)
  $}

  ${
    exan.1 $e |- ( E. x ph /\ ps ) $.
    $( Place a conjunct in the scope of an existential quantifier. $)
    exan $p |- E. x ( ph /\ ps ) $=
      ( wa wex wal hbe1 19.27 ancom mpbi mpgbi 19.29 ax-mp exancom ) BAECFZABEC
      FBCGACFZEZPBQEZRCBQCACHIQBESDQBJKLBACMNBACOK $.
      $( [18-Aug-93] $)
  $}

  $( Split a biconditional and distribute quantifier. $)
  albi $p |- ( A. x ( ph <-> ps ) <->
             ( A. x ( ph -> ps ) /\ A. x ( ps -> ph ) ) ) $=
    ( wb wal wi wa bi bial 19.26 bitr ) ABDZCEABFZBAFZGZCEMCENCEGLOCABHIMNCJK
    $.
    $( [18-Aug-93] $)

  $( Split a biconditional and distribute 2 quantifiers. $)
  2albi $p |- ( A. x A. y ( ph <-> ps ) <->
             ( A. x A. y ( ph -> ps ) /\ A. x A. y ( ps -> ph ) ) ) $=
    ( wb wal wi wa albi bial 19.26 bitr ) ABEDFZCFABGDFZBAGDFZHZCFNCFOCFHMPCABD
    IJNOCKL $.
    $( [5-Feb-05] $) $( [3-Feb-05] $)

  ${
    hbnd.1 $e |- ( ph -> A. x ph ) $.
    hbnd.2 $e |- ( ph -> ( ps -> A. x ps ) ) $.
    $( A deduction form of bound-variable hypothesis builder ~ hbne . $)
    hbnd $p |- ( ph -> ( -. ps -> A. x -. ps ) ) $=
      ( wal wi wn 19.21ai hbnt syl ) ABBCFGZCFBHZMCFGALCDEIBCJK $.
      $( [3-Jan-02] $)
  $}

  ${
    hbimd.1 $e |- ( ph -> A. x ph ) $.
    hbimd.2 $e |- ( ph -> ( ps -> A. x ps ) ) $.
    hbimd.3 $e |- ( ph -> ( ch -> A. x ch ) ) $.
    $( Deduction form of bound-variable hypothesis builder ~ hbim . $)
    hbimd $p |- ( ph -> ( ( ps -> ch ) -> A. x ( ps -> ch ) ) ) $=
      ( wi wal wn hbnd com12 pm2.21 19.20i syl6 ax-1 ja ) BCHZARDIZBCASHBJZATDI
      ZSATUAABDEFKLTRDBCMNOCACDIZSACUBGLCRDCBPNOQL $.
      $( [1-Jan-02] $)
  $}

  ${
    hband.1 $e |- ( ph -> ( ps -> A. x ps ) ) $.
    hband.2 $e |- ( ph -> ( ch -> A. x ch ) ) $.
    $( Deduction form of bound-variable hypothesis builder ~ hban . $)
    hband $p |- ( ph -> ( ( ps /\ ch ) -> A. x ( ps /\ ch ) ) ) $=
      ( wa wal anim12d 19.26 syl6ibr ) ABCGZBDHZCDHZGLDHABMCNEFIBCDJK $.
      $( [2-Jan-02] $)
  $}

  ${
    hbbid.1 $e |- ( ph -> A. x ph ) $.
    hbbid.2 $e |- ( ph -> ( ps -> A. x ps ) ) $.
    hbbid.3 $e |- ( ph -> ( ch -> A. x ch ) ) $.
    $( Deduction form of bound-variable hypothesis builder ~ hbbi . $)
    hbbid $p |- ( ph -> ( ( ps <-> ch ) -> A. x ( ps <-> ch ) ) ) $=
      ( wi wa wal wb hbimd anim12d bi albi 3imtr4g ) ABCHZCBHZIQDJZRDJZIBCKZUAD
      JAQSRTABCDEFGLACBDEGFLMBCNBCDOP $.
      $( [1-Jan-02] $)
  $}

  ${
    hbald.1 $e |- ( ph -> A. y ph ) $.
    hbald.2 $e |- ( ph -> ( ps -> A. x ps ) ) $.
    $( Deduction form of bound-variable hypothesis builder ~ hbal . $)
    hbald $p |- ( ph -> ( A. y ps -> A. x A. y ps ) ) $=
      ( wal 19.20d ax-7 syl6 ) ABDGZBCGZDGKCGABLDEFHBDCIJ $.
      $( [2-Jan-02] $)
  $}

  ${
    hbexd.1 $e |- ( ph -> A. y ph ) $.
    hbexd.2 $e |- ( ph -> ( ps -> A. x ps ) ) $.
    $( Deduction form of bound-variable hypothesis builder ~ hbex . $)
    hbexd $p |- ( ph -> ( E. y ps -> A. x E. y ps ) ) $=
      ( wex wal 19.22d 19.12 syl6 ) ABDGZBCHZDGLCHABMDEFIBDCJK $.
      $( [2-Jan-02] $)
  $}

  $( Closed form of Theorem 19.21 of [Margaris] p. 90. $)
  19.21g $p |- ( A. x ( ph -> A. x ph ) ->
               ( A. x ( ph -> ps ) <-> ( ph -> A. x ps ) ) ) $=
    ( wal wi 19.20 syl3d com12 a4s hba1 ax-4 a1i hbimd syl3 19.20i syl6 impbid
    ) AACDZEZCDZABEZCDZABCDZEZSUBUDECUBSUDUBRUCAABCFGHITUDUDCDUBTAUCCSCJSCKUCUC
    CDETBCJLMUDUACUCBABCKNOPQ $.
    $( [27-May-97] $)

  $( Introduce a conjunct in the scope of an existential quantifier. $)
  exintr $p |- ( A. x ( ph -> ps ) -> ( E. x ph -> E. x ( ph /\ ps ) ) ) $=
    ( wi wal wa hba1 ancl a4s 19.22d ) ABDZCEAABFZCKCGKALDCABHIJ $.
    $( [11-Aug-93] $)

  ${
    aaan.1 $e |- ( ph -> A. y ph ) $.
    aaan.2 $e |- ( ps -> A. x ps ) $.
    $( Rearrange universal quantifiers. $)
    aaan $p |- ( A. x A. y ( ph /\ ps ) <-> ( A. x ph /\ A. y ps ) ) $=
      ( wa wal 19.28 bial hbal 19.27 bitr ) ABGDHZCHABDHZGZCHACHOGNPCABDEIJAOCB
      CDFKLM $.
      $( [12-Aug-93] $)
  $}

  ${
    eeor.1 $e |- ( ph -> A. y ph ) $.
    eeor.2 $e |- ( ps -> A. x ps ) $.
    $( Rearrange existential quantifiers. $)
    eeor $p |- ( E. x E. y ( ph \/ ps ) <-> ( E. x ph \/ E. y ps ) ) $=
      ( wo wex 19.45 biex hbex 19.44 bitr ) ABGDHZCHABDHZGZCHACHOGNPCABDEIJAOCB
      CDFKLM $.
      $( [8-Aug-94] $)
  $}

  $( Quantified "excluded middle".  Exercise 9.2a of Boolos, p. 111,
     _Computability and Logic_. $)
  qexmid $p |- E. x ( ph -> A. x ph ) $=
    ( wal 19.8a 19.35ri ) AABCZBFBDE $.
    $( [10-Dec-00] $)

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Axioms for the equality predicate
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

$(
$)

  $( Declare the equality predicate symbol. $)
  $c = $.  $( Equal sign (read:  'is equal to') $)

  $( Extend wff definition to include atomic formulas using the equality
     predicate. $)
  weq $a wff x = y $.

  $( Axiom of Equality.  One of the 5 equality axioms of predicate calculus.
     This is similar to, but not quite, a transitive law for equality (proved
     later as ~ equtr ).  Axiom scheme C8' in [Megill] p. 448  (p. 16 of the
     preprint).  Also appears as Axiom C7 of [Monk2] p. 105.

     Axioms ~ ax-8 through ~ ax-16 are the axioms having to do with
     equality, substitution, and logical properties of our binary predicate
     ` e. ` (which later in set theory will mean "is a member of").  Note
     that all axioms except ~ ax-16 and ~ ax-17 are still valid even when
     ` x ` , ` y ` , and ` z ` are replaced with the same variable because they
     do not have any distinct variable (Metamath's $d) restrictions.  Distinct
     variable restrictions are required for ~ ax-16 and ~ ax-17 only. $)
  ax-8 $a |- ( x = y -> ( x = z -> y = z ) ) $.

  $( Axiom of Existence.  One of the 5 equality axioms of equality in predicate
     calculus.  This axiom in effect tells us that at least one thing exists.
     In this form (not requiring ` x ` and ` y ` to be distinct) it was used
     in an axiom system of Tarski (see Axiom B7' in footnote 1 of
     [KalishMontague] p. 81.)  It is equivalent to axiom scheme C10' in
     [Megill] p. 448 (p. 16 of the preprint); the equivalence is established by
     ~ ax9 and ~ ax9a .  A more convenient form of this axiom is ~ a9e . $)
  ax-9 $a |- -. A. x -. x = y $.

  $( Axiom of Quantifier Substitution.  One of the 5 equality axioms of
     predicate calculus.  This is a technical axiom wherein the antecedent
     is true only if ` x ` and ` y ` are the same variable, and in that
     case it doesn't matter which one you use in a quantifier.  Axiom scheme
     C11' in [Megill] p. 448  (p. 16 of the preprint).  It apparently does not
     otherwise appear in the literature but is easily proved from textbook
     predicate calculus by cases.  (Strictly speaking, the antecedent is
     also true when ` x ` and ` y ` are different variables in the case of
     a one-element domain of discourse, but then the consequent is also
     true in a one-element domain.  For compatibility with traditional
     predicate calculus all our predicate calculus axioms hold in a one-element
     domain, but this becomes unimportant in set theory where we show in ~ dtru
     that at least 2 things exist.) $)
  ax-10 $a |- ( A. x x = y -> ( A. x ph -> A. y ph ) ) $.

  $( Axiom of Variable Substitution.  One of the 5 equality axioms of predicate
     calculus.  The antecedent becomes false if the same variable is
     substituted for ` x ` and ` y ` , ensuring the axiom is sound whenever
     this is the case.  The final consequent ` A. x ( x = y -> ph ) ` is a way
     of expressing " ` y ` substituted for ` x ` in wff ` ph ` ".  Axiom scheme
     C15' in [Megill] p. 448  (p. 16 of the preprint).  It is based on Axiom C8
     of [Monk2] p. 105, from which it is easily proved by cases.  To
     understand this easier, think of ` -. A. x x = y -> ` ... as an informal
     equivalent for "if ` x ` and ` y ` are distinct variables then..."
     In some later theorems we call an antecedent of the form ` -. A. x x = y `
     a "distinctor".  $)
  ax-11 $a |- ( -. A. x x = y ->
               ( x = y -> ( ph -> A. x ( x = y -> ph ) ) ) ) $.

  $( Axiom of Quantifier Introduction.  One of the 5 equality axioms of
     predicate calculus.  Informally, it says that whenever ` z ` is distinct
     from ` x ` and ` y ` , and ` x = y ` is true, then ` x = y ` quantified
     with ` z ` is also true.  In other words, ` z ` is irrelevant to the
     truth of ` x = y ` .  Axiom scheme C9' in [Megill] p. 448  (p. 16 of
     the preprint).  It apparently does not otherwise appear in the literature
     but is easily proved from textbook predicate calculus by cases. $)
  ax-12 $a |- ( -. A. z z = x -> ( -. A. z z = y ->
              ( x = y -> A. z x = y ) ) ) $.

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        The axioms for a binary non-logical predicate
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

$(
   Introduce a binary non-logical predicate symbol.  We will use it
   for the membership predicate of set theory, but this is irrelevant at this
   point:  these axioms apply to any arbitrary binary predicate symbol.  The
   term 'non-logical' means that the predicate is presumed to have additional
   properties beyond the realm of predicate calculus.  The term 'binary' means
   that the predicate has two arguments.
$)

  $( Declare the membership predicate symbol. $)
  $c e. $. $( Stylized epsilon $)

  $( Extend wff definition to include atomic formulas with the epsilon
     (membership) predicate.  This is read " ` x ` is an element of ` y ` ,"
     " ` x ` is a member of ` y ` ," " ` x ` belongs to ` y ` ," or " ` y `
     contains ` x ` ."   Note:  The phrase " ` y ` includes ` x ` " means
     " ` x ` is a subset of ` y ` "; to use it also for ` x e. y ` (as some
     authors occasionally do) is poor form and causes confusion. $)
  wel $a wff x e. y $.

  $( Axiom of Equality.  One of the 3 non-logical predicate axioms of our
     predicate calculus.  It substitutes equal variables into the left-hand
     side of the ` e. ` binary predicate.  Axiom scheme C12' in [Megill]
     p. 448  (p. 16 of the preprint).  It is a special case of Axiom B8
     (p. 75) of system S2 of [Tarski] p. 77.  "Non-logical" means that the
     predicate is not a primitive of predicate calculus proper but instead is
     an extension to it.  "Binary" means that the predicate has two
     arguments. $)
  ax-13 $a |- ( x = y -> ( x e. z -> y e. z ) ) $.

  $( Axiom of Equality.  One of the 3 non-logical predicate axioms of our
     predicate calculus.  It substitutes equal variables into the right-hand
     side of the ` e. ` binary predicate.  Axiom scheme C13' in [Megill]
     p. 448  (p. 16 of the preprint).  It is a special case of Axiom B8
     (p. 75) of system S2 of [Tarski] p. 77. $)
  ax-14 $a |- ( x = y -> ( z e. x -> z e. y ) ) $.

  $( Axiom of Quantifier Introduction.  One of the 3 non-logical predicate
     axioms of our predicate calculus.  Axiom scheme C14' in [Megill] p. 448
     (p. 16 of the preprint).  It is redundant if we include ~ ax-17 ; see
     theorem ~ ax15 below.  Alternately, ~ ax-17 becomes unnecessary in
     principle with this axiom, but we lose the more powerful metalogic
     afforded by ~ ax-17 . We retain ~ ax-15 here to provide completeness for
     systems with the simpler metalogic that results from omitting ~ ax-17 ,
     which might be easier to study for some theoretical purposes.  $)
  ax-15 $a |- ( -. A. z z = x -> ( -. A. z z = y ->
              ( x e. y -> A. z x e. y ) ) ) $.

  $( This is a variant of ~ ax-9 .  Axiom scheme C10' in [Megill] p. 448 (p. 16
     of the preprint). $)
  ax9 $p |- ( A. x ( x = y -> A. x ph ) -> ph ) $=
    ( weq wal wi wex wn ax-9 df-ex mpbir 19.22 mpi a6e syl ) BCDZABEZFBEZQBGZAR
    PBGZSTPHBEHBCIPBJKPQBLMABNO $.
    $( [5-Aug-93] $)

  $( This theorem is a re-derivation of ~ ax-9 from ~ ax9 . This shows that
     ~ ax-9 and ~ ax9 are interchangeable in the presence of the other
     axioms.  Lemma L18 in [Megill] p. 446 (p. 14 of the preprint).  Use it
     instead of ~ ax-9 so we interchange ~ ax-9 and ~ ax9 as our axiom.  $)
  ax9a $p |- -. A. x -. x = y $=
    ( weq wn wal wi ax9 ax-6 a3i mpg ) ABCZKDZAEDZAEZFMAMABGNKLAHIJ $.
    $( [5-Aug-93] $)

  $( At least one individual exists. $)
  a9e $p |- E. x x = y $=
    ( weq wex wn wal ax9a df-ex mpbir ) ABCZADJEAFEABGJAHI $.
    $( [5-Aug-93] $)

  $( Identity law for equality (reflexivity).  Lemma 6 of [Tarski] p. 68.
     This is often an axiom of equality in textbook systems, but we don't need
     it as an axiom since it can be proved from our other axioms (although
     the proof, as you can see below, is not as obvious as you might think).
     This proof uses only axioms without distinct variable conditions and thus
     involves no dummy variables.  A shorter proof, similar to Tarki's, is
     possible if we make use of ~ ax-17 ; see the proof of ` x = x ` on the
     Metamath Solitaire page.  $)
  equid $p |- x = x $=
    ( weq wal wn wi ax-12 pm2.43i 19.20i ax9 syl ax-6 pm2.61i ) AABZACZDZACZMPM
    NEZACMOQAOQAAAFGHMAAIJMAKL $.
    $( [5-Aug-93] $)

  $( One of the two equality axioms of standard predicate calculus, called
     reflexivity of equality.  (The other one is ~ stdpc7 .)  Axiom 6 of
     [Mendelson] p. 95.  It is not clear why Mendelson prepends the redundant
     quantifier. $)
  stdpc6 $p |- A. x x = x $=
    ( weq equid ax-gen ) AABAACD $.
    $( [16-Feb-05] $) $( [16-Feb-05] $)

  $( Commutative law for equality.  Lemma 7 of [Tarski] p. 69. $)
  equcomi $p |- ( x = y -> y = x ) $=
    ( weq equid ax-8 mpi ) ABCAACBACADABAEF $.
    $( [5-Aug-93] $)

  $( Commutative law for equality. $)
  equcom $p |- ( x = y <-> y = x ) $=
    ( weq equcomi impbi ) ABCBACABDBADE $.
    $( [20-Aug-93] $)

  ${
    equcoms.1 $e |- ( x = y -> ph ) $.
    $( An inference commuting equality in antecedent.  Used to eliminate the
       need for a syllogism. $)
    equcoms $p |- ( y = x -> ph ) $=
      ( weq equcomi syl ) CBEBCEACBFDG $.
      $( [5-Aug-93] $)
  $}

  $( A transitive law for equality. $)
  equtr $p |- ( x = y -> ( y = z -> x = z ) ) $=
    ( weq wi ax-8 equcoms ) BCDACDEBABACFG $.
    $( [23-Aug-93] $)

  $( A transitive law for equality.  Lemma L17 in [Megill] p. 446
     (p. 14 of the preprint). $)
  equtrr $p |- ( x = y -> ( z = x -> z = y ) ) $=
    ( weq equtr com12 ) CADABDCBDCABEF $.
    $( [23-Aug-93] $)

  $( A transitive law for equality. $)
  equtr2 $p |- ( ( x = z /\ y = z ) -> x = y ) $=
    ( weq equtr equcomi syl5 imp ) ACDZBCDZABDZICBDKJACBEBCFGH $.
    $( [12-Aug-93] $)

  $( An equivalence law for equality. $)
  equequ1 $p |- ( x = y -> ( x = z <-> y = z ) ) $=
    ( weq ax-8 equtr impbid ) ABDACDBCDABCEABCFG $.
    $( [5-Aug-93] $)

  $( An equivalence law for equality. $)
  equequ2 $p |- ( x = y -> ( z = x <-> z = y ) ) $=
    ( weq equtrr wi equcoms impbid ) ABDCADZCBDZABCEJIFBABACEGH $.
    $( [5-Aug-93] $)

  $( An identity law for the non-logical predicate. $)
  elequ1 $p |- ( x = y -> ( x e. z <-> y e. z ) ) $=
    ( weq wel ax-13 wi equcoms impbid ) ABDACEZBCEZABCFKJGBABACFHI $.
    $( [5-Aug-93] $)

  $( An identity law for the non-logical predicate. $)
  elequ2 $p |- ( x = y -> ( z e. x <-> z e. y ) ) $=
    ( weq wel ax-14 wi equcoms impbid ) ABDCAEZCBEZABCFKJGBABACFHI $.
    $( [5-Aug-93] $)

  $( Commutation law for identical variable specifiers.  The antecedent and
     consequent are true when ` x ` and ` y ` are substituted with the same
     variable. $)
  alequcom $p |- ( A. x x = y -> A. y y = x ) $=
    ( weq wal ax-10 pm2.43i equcomi 19.20i syl ) ABCZADZJBDZBACZBDKLJABEFJMBABG
    HI $.
    $( [5-Aug-93] $)

  ${
    alequcoms.1 $e |- ( A. x x = y -> ph ) $.
    $( A commutation rule for identical variable specifiers. $)
    alequcoms $p |- ( A. y y = x -> ph ) $=
      ( weq wal alequcom syl ) CBECFBCEBFACBGDH $.
      $( [5-Aug-93] $)
  $}

  ${
    nalequcoms.1 $e |- ( -. A. x x = y -> ph ) $.
    $( A commutation rule for distinct variable specifiers. $)
    nalequcoms $p |- ( -. A. y y = x -> ph ) $=
      ( weq wal alequcom nsyl4 con1i ) ACBECFZBCEBFJABCGDHI $.
      $( [2-Jan-02] $)
  $}

  $( All variables are effectively bound in an identical variable specifier. $)
  hbae $p |- ( A. x x = y -> A. z A. x x = y ) $=
    ( weq wal wi wn ax-12 ax-4 syl7 ax-10 alequcoms pm2.43i syl5 pm2.61ii a5i
    ax-7 syl ) ABDZAEZSCEZAETCESUAACADCEZCBDCEZTUAFZUBGUCGSUATABCHSAIJUDACSACKL
    UDBCBCDBESBEZUATSBCKTUESABKMNLOPSACQR $.
    $( [5-Aug-93] $)

  ${
    hbalequs.1 $e |- ( A. z A. x x = y -> ph ) $.
    $( Rule that applies ~ hbae to antecedent. $)
    hbaes $p |- ( A. x x = y -> ph ) $=
      ( weq wal hbae syl ) BCFBGZJDGABCDHEI $.
      $( [5-Aug-93] $)
  $}

  $( All variables are effectively bound in a distinct variable specifier.
     Lemma L19 in [Megill] p. 446 (p. 14 of the preprint). $)
  hbnae $p |- ( -. A. x x = y -> A. z -. A. x x = y ) $=
    ( weq wal hbae hbne ) ABDAECABCFG $.
    $( [5-Aug-93] $)

  ${
    hbnalequs.1 $e |- ( A. z -. A. x x = y -> ph ) $.
    $( Rule that applies ~ hbnae to antecedent. $)
    hbnaes $p |- ( -. A. x x = y -> ph ) $=
      ( weq wal wn hbnae syl ) BCFBGHZKDGABCDIEJ $.
      $( [5-Aug-93] $)
  $}

  $( Lemma used in proofs of substitution properties. $)
  equs1 $p |- ( A. x ( x = y -> ph ) -> -. A. x ( x = y -> -. ph ) ) $=
    ( weq wi wal wn ax-4 msca hbn1 syl6 a5i ax9 syl ) BCDZAEZBFZOOAGEZBFZGZBFZE
    ZBFTPUBBQOTUAQOASPBHRBHIRBJKLTBCMN $.
    $( [5-Aug-93] $)

  $( Lemma used in proofs of substitution properties. $)
  equs2 $p |- ( -. A. x x = y ->
          ( -. A. x ( x = y -> -. ph ) -> A. x ( x = y -> ph ) ) ) $=
    ( weq wal wn wi hbnae hbn1 ax-11 con1 syl6 com23 19.21ad ) BCDZBEFZOAFZGZBE
    ZFZOAGBBCBHRBIPOTAPOQSGTAGQBCJASKLMN $.
    $( [25-Apr-94] $)

  $( Lemma used in proofs of substitution properties. $)
  equs3 $p |- ( E. x ( x = y /\ ph ) <-> -. A. x ( x = y -> -. ph ) ) $=
    ( weq wn wi wal wa wex alinexa bicon2i ) BCDZAEFBGLAHBILABJK $.
    $( [5-Aug-93] $)

  $( Lemma used in proofs of substitution properties. $)
  equs4 $p |- ( A. x ( x = y -> ph ) -> E. x ( x = y /\ ph ) ) $=
    ( weq wi wal wn wa wex equs1 equs3 sylibr ) BCDZAEBFMAGEBFGMAHBIABCJABCKL
    $.
    $( [5-Aug-93] $)

  $( Lemma used in proofs of substitution properties. $)
  equs5 $p |- ( -. A. x x = y ->
             ( E. x ( x = y /\ ph ) -> A. x ( x = y -> ph ) ) ) $=
    ( weq wal wn wi wa wex equs2 equs3 syl5ib ) BCDZBEFMAFGBEFMAGBEMAHBIABCJABC
    KL $.
    $( [5-Aug-93] $)

  ${
    equsal.1 $e |- ( ps -> A. x ps ) $.
    equsal.2 $e |- ( x = y -> ( ph <-> ps ) ) $.
    $( A useful equivalence related to substitution. $)
    equsal $p |- ( A. x ( x = y -> ph ) <-> ps ) $=
      ( weq wi wal 19.3r syl6bb pm5.74i bial ax-1 a5i syl ax9 impbi bitr4 ) CDG
      ZAHZCITBCIZHZCIZBUAUCCTAUBTABUBFBCEJKLMBUDBUBUDEBUCCUBTNOPBCDQRS $.
      $( [5-Aug-93] $)
  $}

  ${
    equsex.1 $e |- ( ps -> A. x ps ) $.
    equsex.2 $e |- ( x = y -> ( ph <-> ps ) ) $.
    $( A useful equivalence related to substitution. $)
    equsex $p |- ( E. x ( x = y /\ ph ) <-> ps ) $=
      ( weq wn wi wex wal wa exnal df-an biex hbne negbid equsal bicon2i
      3bitr4 ) CDGZAHZIZHZCJUCCKZHUAALZCJBUCCMUFUDCUAANOUEBUBBHCDBCEPUAABFQRST
      $.
      $( [5-Aug-93] $)
  $}

  ${
    dral1OLD.1 $e |- ( A. x x = y -> ( ph -> ps ) ) $.
    $( Formula-building lemma for use with the Distinctor Reduction Theorem.
       Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
    dral1OLD $p |- ( A. x x = y -> ( A. x ph -> A. y ps ) ) $=
      ( weq wal wi 19.20ii hbaes ax-10 syld ) CDFCGZACGZBCGZBDGNOHCDCMABCEIJBCD
      KL $.
      $( [5-Aug-93] $)
  $}

  ${
    dral2OLD.1 $e |- ( A. x x = y -> ( ph -> ps ) ) $.
    $( Formula-building lemma for use with the Distinctor Reduction Theorem.
       Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
    dral2OLD $p |- ( A. x x = y -> ( A. y ph -> A. x ps ) ) $=
      ( weq wal wi 19.20ii hbaes ax-10 alequcoms syld ) CDFCGZADGZBDGZBCGZOPHCD
      DNABDEIJPQHDCBDCKLM $.
      $( [5-Aug-93] $)
  $}

  ${
    dral1.1 $e |- ( A. x x = y -> ( ph <-> ps ) ) $.
    $( Formula-building lemma for use with the Distinctor Reduction Theorem.
       Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
    dral1 $p |- ( A. x x = y -> ( A. x ph <-> A. y ps ) ) $=
      ( weq wal wi biimpd 19.20ii hbaes ax-10 syld biimprd alequcoms impbid )
      CDFCGZACGZBDGZQRBCGZSRTHCDCQABCQABEIJKBCDLMQSADGZRSUAHCDDQBADQABENJKUARHD
      CADCLOMP $.
      $( [24-Nov-94] $)
  $}

  ${
    dral3OLD.1 $e |- ( A. x x = y -> ( ph -> ps ) ) $.
    $( Formula-building lemma for use with the Distinctor Reduction Theorem.
       Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
    dral3OLD $p |- ( A. x x = y -> ( A. z ph -> A. z ps ) ) $=
      ( wal wi weq 19.20ii hbaes ) AEGBEGHCDECDICGABEFJK $.
      $( [5-Aug-93] $)
  $}

  ${
    dral2.1 $e |- ( A. x x = y -> ( ph <-> ps ) ) $.
    $( Formula-building lemma for use with the Distinctor Reduction Theorem.
       Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
    dral2 $p |- ( A. x x = y -> ( A. z ph <-> A. z ps ) ) $=
      ( weq wal hbae biald ) CDGCHABECDEIFJ $.
      $( [21-Mar-05] $) $( [27-Feb-05] $)
  $}

  ${
    drex1OLD.1 $e |- ( A. x x = y -> ( ph -> ps ) ) $.
    $( Formula-building lemma for use with the Distinctor Reduction Theorem.
       Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
    drex1OLD $p |- ( A. x x = y -> ( E. x ph -> E. y ps ) ) $=
      ( weq wal wn wex con3d dral2OLD df-ex 3imtr4g ) CDFCGZAHZCGZHBHZDGZHACIBDINR
      PQOCDNABEJKJACLBDLM $.
      $( [5-Aug-93] $)
  $}

  ${
    drex1.1 $e |- ( A. x x = y -> ( ph <-> ps ) ) $.
  $}

  ${
    drex2OLD.1 $e |- ( A. x x = y -> ( ph -> ps ) ) $.
    $( Formula-building lemma for use with the Distinctor Reduction Theorem.
       Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
    drex2OLD $p |- ( A. x x = y -> ( E. y ph -> E. x ps ) ) $=
      ( weq wal wn wex con3d dral1OLD df-ex 3imtr4g ) CDFCGZAHZDGZHBHZCGZHADIBCINR
      PQOCDNABEJKJADLBCLM $.
      $( [5-Aug-93] $)
  $}

  ${
    drex3OLD.1 $e |- ( A. x x = y -> ( ph -> ps ) ) $.
    $( Formula-building lemma for use with the Distinctor Reduction Theorem.
       Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
    drex3OLD $p |- ( A. x x = y -> ( E. z ph -> E. z ps ) ) $=
      ( weq wal wn wex con3d dral3OLD df-ex 3imtr4g ) CDGCHZAIZEHZIBIZEHZIAEJBEJOS
      QRPCDEOABFKLKAEMBEMN $.
      $( [5-Aug-93] $)
  $}

  ${
    drex2.1 $e |- ( A. x x = y -> ( ph <-> ps ) ) $.
  $}

  ${
    a4a.1 $e |- ( ps -> A. x ps ) $.
    a4a.2 $e |- ( x = y -> ( ph -> ps ) ) $.
    $( Specialization with implicit substitution.  Compare Lemma 14 of [Tarski]
       p. 70. $)
    a4a $p |- ( A. x ph -> ps ) $=
      ( wal weq wi com12 syl6 19.20i ax9 syl ) ACGCDHZBCGZIZCGBAQCAOBPOABFJEKLB
      CDMN $.
      $( [5-Aug-93] $)
  $}

  ${
    a4c.1 $e |- ( ph -> A. x ph ) $.
    a4c.2 $e |- ( x = y -> ( ph -> ps ) ) $.
    $( Existential introduction with implicit substitution.  Compare Lemma 14
       of [Tarski] p. 70. $)
    a4c $p |- ( ph -> E. x ps ) $=
      ( wn wal wex hbne weq con3d a4a con2i df-ex sylibr ) ABGZCHZGBCIRAQAGCDAC
      EJCDKABFLMNBCOP $.
      $( [7-Aug-94] $)
  $}

  ${
    a4c1.1 $e |- ( ch -> A. x ch ) $.
    a4c1.2 $e |- ( ch -> ( ph -> A. x ph ) ) $.
    a4c1.3 $e |- ( x = y -> ( ph -> ps ) ) $.
    $( A more general version of ~ a4c . $)
    a4c1 $p |- ( ch -> ( ph -> E. x ps ) ) $=
      ( wex wa wal adantr imp jca 19.26 sylibr weq adantld a4c exp ) CABDICAJZB
      DEUACDKZADKZJUADKUAUBUCCUBAFLCAUCGMNCADOPDEQABCHRST $.
      $( [5-Aug-93] $)
  $}

  ${
    cbv1.1 $e |- ( ph -> ( ps -> A. y ps ) ) $.
    cbv1.2 $e |- ( ph -> ( ch -> A. x ch ) ) $.
    cbv1.3 $e |- ( ph -> ( x = y -> ( ps -> ch ) ) ) $.
    $( Rule used to change bound variables with implicit substitution. $)
    cbv1 $p |- ( A. x A. y ph -> ( A. x ps -> A. y ch ) ) $=
      ( wal wi a4s 19.20ii ax-7 syl6 weq com23 syl6d ax9 a7s syld ) AEIZDIZBDIZ
      UCEIZCEIZUBUCBEIZDIUDUABUFDABUFJEFKLBDEMNAUDUEJEDADIZUCCEUGUCDEOZCDIZJZDI
      CABUJDABUHCUIAUHBCHPGQLCDERNLST $.
      $( [5-Aug-93] $)
  $}


  ${
    cbv2.1 $e |- ( ph -> ( ps -> A. y ps ) ) $.
    cbv2.2 $e |- ( ph -> ( ch -> A. x ch ) ) $.
    cbv2.3 $e |- ( ph -> ( x = y -> ( ps <-> ch ) ) ) $.
    $( Rule used to change bound variables with implicit substitution. $)
    cbv2 $p |- ( A. x A. y ph -> ( A. x ps <-> A. y ch ) ) $=
      ( wal weq wb wi bi1 syl6 cbv1 bi2 equcomi syl5 a7s impbid ) AEIDIBDIZCEIZ
      ABCDEFGADEJZBCKZBCLHBCMNOAUBUALEDACBEDGFAUCCBLZEDJAUCUDUEHBCPNEDQROST $.
      $( [5-Aug-93] $)
  $}

  ${
    cbv3.1 $e |- ( ph -> A. y ph ) $.
    cbv3.2 $e |- ( ps -> A. x ps ) $.
    cbv3.3 $e |- ( x = y -> ( ph -> ps ) ) $.
    $( Rule used to change bound variables with implicit substitution. $)
    cbv3 $p |- ( A. x ph -> A. y ps ) $=
      ( wi wal syl3 a1i weq cbv1 id ax-gen mpg ) AAHZDIACIBDIHCQABCDAADIAEJBBCI
      HQFKCDLABHHQGKMQDANOP $.
      $( [5-Aug-93] $)
  $}


  ${
    cbval.1 $e |- ( ph -> A. y ph ) $.
    cbval.2 $e |- ( ps -> A. x ps ) $.
    cbval.3 $e |- ( x = y -> ( ph <-> ps ) ) $.
    $( Rule used to change bound variables with implicit substitution. $)
    cbval $p |- ( A. x ph <-> A. y ps ) $=
      ( wi wal wb syl3 a1i weq cbv2 id ax-gen mpg ) AAHZDIACIBDIJCRABCDAADIAEKB
      BCIHRFLCDMABJHRGLNRDAOPQ $.
      $( [5-Aug-93] $)
  $}

  ${
    cbvex.1 $e |- ( ph -> A. y ph ) $.
    cbvex.2 $e |- ( ps -> A. x ps ) $.
    cbvex.3 $e |- ( x = y -> ( ph <-> ps ) ) $.
    $( Rule used to change bound variables with implicit substitution. $)
    cbvex $p |- ( E. x ph <-> E. y ps ) $=
      ( wn wal wex hbne weq negbid cbval negbii df-ex 3bitr4 ) AHZCIZHBHZDIZHAC
      JBDJSUARTCDADEKBCFKCDLABGMNOACPBDPQ $.
      $( [5-Aug-93] $)
  $}

  ${
    chv2.1 $e |- ( ps -> A. x ps ) $.
    chv2.2 $e |- ( x = y -> ( ph <-> ps ) ) $.
    chv2.3 $e |- ph $.
    $( Implicit substitution of ` y ` for ` x ` into a theorem.  (Contributed
       by Raph Levien, 9-Jul-03.) $)
    chvar $p |- ps $=
      ( weq biimpd a4a mpg ) ABCABCDECDHABFIJGK $.
      $( [29-Jul-03] $)
  $}

  $( A variable introduction law for equality.  Lemma 15 of [Monk2] p. 109,
     however we do not require ` z ` to be distinct from ` x ` and ` y `
     (making the proof longer). $)
  equvini $p |- ( x = y -> E. z ( x = z /\ z = y ) ) $=
    ( weq wal wo wa wex wi a9e equid jctl 19.22i ax-mp ax-8 a4s anim1d drex3OLD
    mpi equcomi jctir ax-1 anim2d jaoi a1d wn ioran hbnae hban ax-12 imp
    anc2li equcoms a4c1 sylbi pm2.61i ) CADZCEZCBDZCEZFZABDZACDZUSGZCHZIZVAVEVB
    URVEUTURCCDZUSGZCHZVEUSCHVICBJUSVHCUSVGCKZLMNVHVDCACURVGVCUSUQVGVCICCACOPQR
    SUTVCVGGZCHZVEUQCHVLCAJUQVKCUQVCVGCATVJUAMNVKVDCBCUTVGUSVCUSVGUSICUSVGUBPUC
    RSUDUEVAUFURUFZUTUFZGZVFURUTUGVBVDVOCAVMVNCCACUHCBCUHUIVMVNVBVBCEIABCUJUKVB
    VDIACVCVBUSACBOULUMUNUOUP $.
    $( [5-Aug-93] $)

  $( Bound-variable hypothesis builder for ` x = x ` that avoids ~ ax-9 .
     (A shorter proof that uses ~ ax-9 is obtainable from ~ equid and
     ~ hbth .) $)
  hbequid $p |- ( x = x -> A. x x = x ) $=
    ( weq wal wn wi ax-12 pm2.43i a4s hbn1 ax-6 19.21ai a1d pm2.61i ) AABZACZDZ
    ACZNOEZPRAPRAAAFGHQDZONSNAPAINAJKLM $.
    $( [17-Feb-05] $) $( [27-Dec-04] $)


$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Substitution
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $c [ $. $( Left bracket $)
  $c / $. $( Division. $)
  $c ] $.  $( Right bracket $)

  $( Extend wff definition to include proper substitution (read "the wff that
     results when ` y ` is properly substituted for ` x ` in wff ` ph ` "). $)
  wsb $a wff [ y / x ] ph $.

  $( Define proper substitution.  Remark 9.1 in [Megill] p. 447 (p. 15 of the
     preprint).  For our notation, we use ` [ y / x ] ph ` to mean "the wff
     that results when ` y ` is properly substituted for ` x ` in the wff
     ` ph ` ."   We can also use ` [ y / x ] ph ` to eliminate the "free for"
     side condition used in traditional predicate calculus; see, for example,
     ~ stdpc4 .

     Our notation was introduced in Haskell B. Curry's _Foundations of
     Mathematical Logic_ (1977), p. 316 and is frequently used in textbooks
     of lambda calculus and combinatory logic.  This notation improves the
     common but ambiguous notation, " ` ph ( y ) ` is the wff that results
     when ` y ` is properly substituted for ` x ` in ` ph ( x ) ` ". For
     example, if the original ` ph ( x ) ` is ` x = y ` , then ` ph ( y ) `
     is ` y = y ` , from which we obtain that ` ph ( x ) ` is ` x = x ` . So
     what exactly does ` ph ( x ) ` mean?  Curry's notation solves this
     problem.

     In most books, proper substitution has a somewhat complicated recursive
     definition with multiple cases based on the occurrences of free and
     bound variables in the wff.  Instead we use a remarkable little formula
     that is exactly equivalent and gives us a single direct definition.  We
     later prove that our definition has the properties we expect of proper
     substitution (see theorems ~ sbequ , ~ sbcom2 and ~ sbid2v ).

     Note that our definition is valid even when ` x ` and ` y ` are replaced
     with the same variable, as ~ sbid shows.  We achieve this by having ` x `
     free in the first conjunct and bound in the second.  We can also achieve
     this by using a dummy variable, as the alternate definition ~ sb7 shows
     (which some logicians may prefer because it doesn't mix free and bound
     variables).  Another version that mixes free and bound variables is
     ~ dfsb2 .  When ` x ` and ` y ` are distinct, we can express proper
     substitution with the simpler expressions of ~ sb5 and ~ sb6 .

     There are no restrictions on any of the variables, including what
     variables may occur in wff ` ph ` . $)
  df-sb $a |- ( [ y / x ] ph <->
              ( ( x = y -> ph ) /\ E. x ( x = y /\ ph ) ) ) $.

  ${
    sbimi.1 $e |- ( ph -> ps ) $.
    $( Infer substitution into antecedent and consequent of an implication. $)
    sbimi $p |- ( [ y / x ] ph -> [ y / x ] ps ) $=
      ( weq wi wa wex wsb syl3 anim2i 19.22i anim12i df-sb 3imtr4 ) CDFZAGZQAHZ
      CIZHQBGZQBHZCIZHACDJBCDJRUATUCABQEKSUBCABQELMNACDOBCDOP $.
      $( [25-Jun-98] $)
  $}

  ${
    bisb.1 $e |- ( ph <-> ps ) $.
    $( Infer substitution into both sides of a logical equivalence. $)
    bisb $p |- ( [ y / x ] ph <-> [ y / x ] ps ) $=
      ( wsb biimp sbimi biimpr impbi ) ACDFBCDFABCDABEGHBACDABEIHJ $.
      $( [5-Aug-93] $)
  $}

  $( Formula-building lemma for use with the Distinctor Reduction Theorem.
     Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
  drsb1OLD $p |- ( A. x x = y -> ( [ z / x ] ph -> [ z / y ] ph ) ) $=
    ( weq wal wi wa wex wsb ax-8 a4s alequcoms syl4d anim1d drex1OLD anim12d
    df-sb 3imtr4g ) BCEZBFZBDEZAGZUBAHZBIZHCDEZAGZUFAHZCIZHABDJACDJUAUCUGUEUIUA
    UFUBAUFUBGZCBCBEUJCCBDKLMNUDUHBCUAUBUFATUBUFGBBCDKLOPQABDRACDRS $.
    $( [5-Aug-93] $)

  $( Formula-building lemma for use with the Distinctor Reduction Theorem.
     Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
  drsb1 $p |- ( A. x x = y -> ( [ z / x ] ph <-> [ z / y ] ph ) ) $=
    ( weq wal wsb wi wa wex ax-8 a4s alequcoms syl4d anim1d drex1OLD anim12d
    df-sb 3imtr4g impbid ) BCEZBFZABDGZACDGZUBBDEZAHZUEAIZBJZIZCDEZAHZUJAIZCJZI
    ZUCUDUBUFUKUHUMUBUJUEAUJUEHZCBCBEZUOCCBDKLZMNUGULBCUBUEUJAUAUEUJHZBBCDKLZOP
    QABDRZACDRZSUDUCHCBUPCFZUNUIUDUCVBUKUFUMUHVBUEUJAURBCUSMNULUGCBVBUJUEAUQOPQ
    VAUTSMT $.
    $( [5-Aug-93] $)

  $( One direction of a simplified definition of substitution. $)
  sb1 $p |- ( [ y / x ] ph -> E. x ( x = y /\ ph ) ) $=
    ( wsb weq wi wa wex df-sb pm3.27bd ) ABCDBCEZAFKAGBHABCIJ $.
    $( [5-Aug-93] $)

  $( One direction of a simplified definition of substitution. $)
  sb2 $p |- ( A. x ( x = y -> ph ) -> [ y / x ] ph ) $=
    ( weq wi wal wa wex wsb ax-4 equs4 jca df-sb sylibr ) BCDZAEZBFZPOAGBHZGABC
    IQPRPBJABCKLABCMN $.
    $( [5-Aug-93] $)

  $( One direction of a simplified definition of substitution when variables
     are distinct. $)
  sb3 $p |- ( -. A. x x = y -> ( E. x ( x = y /\ ph ) -> [ y / x ] ph ) ) $=
    ( weq wal wn wa wex wi wsb equs5 sb2 syl6 ) BCDZBEFNAGBHNAIBEABCJABCKABCLM
    $.
    $( [5-Aug-93] $)

  $( One direction of a simplified definition of substitution when variables
     are distinct. $)
  sb4 $p |- ( -. A. x x = y -> ( [ y / x ] ph -> A. x ( x = y -> ph ) ) ) $=
    ( weq wal wn wa wex wi wsb equs5 sb1 syl5 ) BCDZBEFNAGBHNAIBEABCJABCKABCLM
    $.
    $( [5-Aug-93] $)

  $( Simplified definition of substitution when variables are distinct. $)
  sb4b $p |- ( -. A. x x = y -> ( [ y / x ] ph <-> A. x ( x = y -> ph ) ) ) $=
    ( weq wal wn wsb wi sb4 sb2 a1i impbid ) BCDZBEFZABCGZMAHBEZABCIPOHNABCJKL
    $.
    $( [27-May-97] $)

  $( An equality theorem for substitution. $)
  sbequ1 $p |- ( x = y -> ( ph -> [ y / x ] ph ) ) $=
    ( weq wsb wa wi wex pm3.4 19.8a jca df-sb sylibr exp ) BCDZAABCEZOAFZOAGZQB
    HZFPQRSOAIQBJKABCLMN $.
    $( [5-Aug-93] $)

  $( An equality theorem for substitution. $)
  sbequ2 $p |- ( x = y -> ( [ y / x ] ph -> ph ) ) $=
    ( weq wi wa wex wsb pm3.26 com12 df-sb syl5ib ) BCDZMAEZMAFBGZFZAABCHPMANOI
    JABCKL $.
    $( [5-Aug-93] $)

  $( An alternate definition of proper substitution that, like ~ df-sb , mixes
     free and bound variables to avoid distinct variable requirements. $)
  dfsb2 $p |- ( [ y / x ] ph <->
              ( ( x = y /\ ph ) \/ A. x ( x = y -> ph ) ) ) $=
    ( wsb weq wa wi wal wo ax-4 a1d sbequ2 a4s jcad orc syl6 wn sb4 olc
    pm2.61i sbequ1 imp sb2 jaoi impbi ) ABCDZBCEZAFZUGAGBHZIZUGBHZUFUJGUKUFUHUJ
    UKUFUGAUKUGUFUGBJKUGUFAGBABCLMNUHUIOPUKQUFUIUJABCRUIUHSPTUHUFUIUGAUFABCUAUB
    ABCUCUDUE $.
    $( [18-Feb-05] $) $( [17-Feb-05] $)

  $( One of the two equality axioms of standard predicate calculus, called
     substitutivity of equality.  (The other one is ~ stdpc6 .)  Translated
     to traditional notation, it can be read:
     " ` x = y -> ( ph ( x , x ) -> ph ( x , y ) ) ` , provided that ` y ` is
     free for ` x ` in ` ph ( x , y ) ` ."  Axiom 7 of [Mendelson] p. 95. $)
  stdpc7 $p |- ( x = y -> ( [ x / y ] ph -> ph ) ) $=
    ( wsb wi sbequ2 equcoms ) ACBDAECBACBFG $.
    $( [15-Feb-05] $) $( [15-Feb-05] $)

  $( An equality theorem for substitution. $)
  sbequ12 $p |- ( x = y -> ( ph <-> [ y / x ] ph ) ) $=
    ( weq wsb sbequ1 sbequ2 impbid ) BCDAABCEABCFABCGH $.
    $( [5-Aug-93] $)

  $( An equality theorem for substitution. $)
  sbequ12r $p |- ( x = y -> ( [ x / y ] ph <-> ph ) ) $=
    ( weq wsb wb sbequ12 equcom bicom 3imtr4 ) CBDAACBEZFBCDKAFACBGBCHKAIJ $.
    $( [7-Oct-04] $) $( [6-Oct-04] $)

  $( An equality theorem for substitution. $)
  sbequ12a $p |- ( x = y -> ( [ y / x ] ph <-> [ x / y ] ph ) ) $=
    ( weq wsb sbequ12 wb equcoms bitr3d ) BCDAABCEACBEZABCFAJGCBACBFHI $.
    $( [5-Aug-93] $)

  $( An identity theorem for substitution.  Remark 9.1 in [Megill] p. 447
     (p. 15 of the preprint). $)
  sbid $p |- ( [ x / x ] ph <-> ph ) $=
    ( wsb weq wb equid sbequ12 ax-mp bicomi ) AABBCZBBDAJEBFABBGHI $.
    $( [5-Aug-93] $)

  $( The specialization axiom of standard predicate calculus.  It states that
     if a statement ` ph ` holds for all ` x ` , then it also holds for the
     specific case of ` y ` (properly) substituted for ` x ` .  Translated to
     traditional notation, it can be read:  " ` A. x ph ( x ) -> ph ( y ) ` ,
     provided that ` y ` is free for ` x ` in ` ph ( x ) ` ."  Axiom 4 of
     [Mendelson] p. 69. $)
  stdpc4 $p |- ( A. x ph -> [ y / x ] ph ) $=
    ( wal weq wi wsb ax-1 19.20i sb2 syl ) ABDBCEZAFZBDABCGAMBALHIABCJK $.
    $( [5-Aug-93] $)

  ${
    sbf.1 $e |- ( ph -> A. x ph ) $.
    $( Substitution for a variable not free in a wff does not affect it. $)
    sbf $p |- ( [ y / x ] ph <-> ph ) $=
      ( wsb weq wex wa sb1 19.41 sylib pm3.27d wal stdpc4 syl impbi ) ABCEZAQBC
      FZBGZAQRAHBGSAHABCIRABDJKLAABMQDABCNOP $.
      $( [17-Oct-04] $) $( [5-Aug-93] $)
  $}

  ${
    sb6x.1 $e |- ( ph -> A. x ph ) $.
    $( Equivalence involving substitution for a variable not free. $)
    sb6x $p |- ( [ y / x ] ph <-> A. x ( x = y -> ph ) ) $=
      ( wsb weq wi wal sbf ax-1 19.21ai sylbi sb2 impbi ) ABCEZBCFZAGZBHZOARABC
      DIAQBDAPJKLABCMN $.
      $( [5-Aug-93] $)
  $}

  ${
    sb6y.1 $e |- ( ph -> A. y ph ) $.
    $( Equivalence involving substitution with a variable not free. $)
    sb6y $p |- ( [ y / x ] ph <-> A. x ( x = y -> ph ) ) $=
      ( wsb weq wi wal sbequ2 a4s ax-10 alequcoms ax-1 19.20i syl6 syl5 syld
      sb4 pm2.61i sb2 impbi ) ABCEZBCFZAGZBHZUCBHZUBUEGUFUBAUEUCUBAGBABCIJUFACH
      ZUEAUFUGABHZUEUGUHGCBACBKLAUDBAUCMNODPQABCRSABCTUA $.
      $( [5-Aug-93] $)
  $}

  $( Substitution with a distinct variable makes the substituted variable not
     free. $)
  hbsb2 $p |- ( -. A. x x = y -> ( [ y / x ] ph -> A. x [ y / x ] ph ) ) $=
    ( weq wal wn wsb wi sb4 sb2 a5i syl6 ) BCDZBEFABCGZMAHZBENBEABCIONBABCJKL
    $.
    $( [5-Aug-93] $)

  ${
    hbs1f.1 $e |- ( ph -> A. x ph ) $.
    $( If ` x ` is not free in ` ph ` , it is not free in ` [ y / x ] ph ` . $)
    hbs1f $p |- ( [ y / x ] ph -> A. x [ y / x ] ph ) $=
      ( wsb wal weq wex wa sb1 19.41 sylib pm3.27d stdpc4 a5i 3syl ) ABCEZAABFQ
      BFQBCGZBHZAQRAIBHSAIABCJRABDKLMDAQBABCNOP $.
      $( [5-Aug-93] $)
  $}

  ${
    hbsb3.1 $e |- ( ph -> A. y ph ) $.
    $( If ` y ` is not free in ` ph ` , ` x ` is not free in
       ` [ y / x ] ph ` . $)
    hbsb3 $p |- ( [ y / x ] ph -> A. x [ y / x ] ph ) $=
      ( weq wal wsb wi sbequ2 a4s ax-10 alequcoms syl5 syld sbequ1 19.20ii
      hbsb2 pm2.61i ) BCEZBFZABCGZUABFZHTUAABFZUBTUAAUCSUAAHBABCIJTACFZUCAUDUCH
      CBACBKLDMNSAUABABCOPNABCQR $.
      $( [5-Aug-93] $)
  $}

  $( An equality theorem for substitution. $)
  sbequi $p |- ( x = y -> ( [ x / z ] ph -> [ y / z ] ph ) ) $=
    ( weq wal wsb wi wn wa wex hbsb2 equvini sbequ2 equcoms sbequ1 sylan9
    19.22i syl 19.35 sylib hbnae 19.9d syl9 exp com23 a4s adantr drsb1OLD
    alequcoms sylan9r syld pm2.61ii ) DBEZDFZDCEZDFZBCEZADBGZADCGZHZHUOIZURUQIZ
    VAVBURVCVAHVBURJUSUTDKZVCUTVBUSUSDFZURVDADBLURVADKZVEVDHURBDEZUPJZDKVFBCDMV
    HVADVGUSAUPUTUSAHZDBADBNZOADCPZQRSUSUTDTUAQUTVCDDCDUBADCLUCUDUEUFUOURVAUOUR
    JUSAUTUOVIURUNVIDVJUGUHURAABCGZUOUTABCPVLUTHBDABDCUIUJUKULUEUQURVAUQURJUSAU
    TUQUSACBGZURAADCBUIVMAHCBACBNOQUQAUTHZURUPVNDVKUGUHULUEUM $.
    $( [5-Aug-93] $)

  $( An equality theorem for substitution.  Used in proof of Theorem 9.7
     in [Megill] p. 449 (p. 16 of the preprint). $)
  sbequ $p |- ( x = y -> ( [ x / z ] ph <-> [ y / z ] ph ) ) $=
    ( weq wsb sbequi wi equcoms impbid ) BCEADBFZADCFZABCDGLKHCBACBDGIJ $.
    $( [5-Aug-93] $)

  $( Formula-building lemma for use with the Distinctor Reduction Theorem.
     Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
  drsb2OLD $p |- ( A. x x = y -> ( [ x / z ] ph -> [ y / z ] ph ) ) $=
    ( weq wsb wi sbequi a4s ) BCEADBFADCFGBABCDHI $.
    $( [5-Aug-93] $)

  $( Formula-building lemma for use with the Distinctor Reduction Theorem.
     Part of Theorem 9.4 of [Megill] p. 448 (p. 16 of preprint). $)
  drsb3OLD $p |- ( A. x x = y -> ( [ y / z ] ph -> [ x / z ] ph ) ) $=
    ( weq wsb wi sbequi equcoms a4s ) BCEADCFADBFGZBKCBACBDHIJ $.
    $( [5-Aug-93] $)


  $( Removal of negation from substitution. $)
  sbn1 $p |- ( [ y / x ] -. ph -> -. [ y / x ] ph ) $=
    ( weq wal wn wsb wi sbequ2 con3d syld a4s sb4 wa wex sb1 equs3 sylib con2i
    syl6 pm2.61i ) BCDZBEZAFZBCGZABCGZFZHZUBUHBUBUEUDUGUDBCIUBUFAABCIJKLUCFUEUB
    UDHBEZUGUDBCMUFUIUFUBANBOUIFABCPABCQRSTUA $.
    $( [7-Aug-94] $)

  $( Introduction of negation into substitution. $)
  sbn2 $p |- ( -. [ y / x ] ph -> [ y / x ] -. ph ) $=
    ( wsb wn weq wi wa wex sbequ1 con3d com12 wal sb2 pm4.13 bisb sylibr con3i
    equs3 jca df-sb ) ABCDZEZBCFZAEZGZUDUEHBIZHUEBCDUCUFUGUDUCUEUDAUBABCJKLUCUD
    UEEZGBMZEUGUIUBUIUHBCDUBUHBCNAUHBCAOPQRUEBCSQTUEBCUAQ $.
    $( [7-Aug-94] $)

  $( Negation inside and outside of substitution are equivalent. $)
  sbn $p |- ( [ y / x ] -. ph <-> -. [ y / x ] ph ) $=
    ( wn wsb sbn1 sbn2 impbi ) ADBCEABCEDABCFABCGH $.
    $( [5-Aug-93] $)

  ${
    sb5y.1 $e |- ( ph -> A. y ph ) $.
    $( Equivalence involving substitution with a variable not free. $)
    sb5y $p |- ( [ y / x ] ph <-> E. x ( x = y /\ ph ) ) $=
      ( wsb weq wn wi wal wa wex hbne sb6y sbn bitr3 bicon2i equs3 bitr4 ) ABCE
      ZBCFZAGZHBIZGTAJBKUBSUBUABCESGUABCACDLMABCNOPABCQR $.
      $( [5-Aug-93] $)
  $}

  $( Removal of implication from substitution. $)
  sbi1 $p |- ( [ y / x ] ( ph -> ps ) -> ( [ y / x ] ph -> [ y / x ] ps ) ) $=
    ( weq wal wi wsb sbequ2 syl5d sbequ1 syl6d a4s wn sb4 ax-2 19.20ii sb2
    syl6 pm2.61i ) CDEZCFZABGZCDHZACDHZBCDHZGGZUAUGCUAUDUEBUFUAUDABUEUCCDIACDIJ
    BCDKLMUBNZUDUAAGZCFZUFUEUHUDUAUCGZCFZUJUFGUCCDOULUJUABGZCFUFUKUIUMCUAABPQBC
    DRSSACDOJT $.
    $( [5-Aug-93] $)

  $( Introduction of implication into substitution. $)
  sbi2 $p |- ( ( [ y / x ] ph -> [ y / x ] ps ) -> [ y / x ] ( ph -> ps ) ) $=
    ( wsb wi wn sbn pm2.21 sbimi sylbir ax-1 ja ) ACDEZBCDEABFZCDEZNGAGZCDEPACD
    HQOCDABIJKBOCDBALJM $.
    $( [5-Aug-93] $)

  $( Implication inside and outside of substitution are equivalent. $)
  sbim $p |- ( [ y / x ] ( ph -> ps ) <-> ( [ y / x ] ph -> [ y / x ] ps ) ) $=
    ( wi wsb sbi1 sbi2 impbi ) ABECDFACDFBCDFEABCDGABCDHI $.
    $( [5-Aug-93] $)

  $( Logical OR inside and outside of substitution are equivalent. $)
  sbor $p |- ( [ y / x ] ( ph \/ ps ) <-> ( [ y / x ] ph \/ [ y / x ] ps ) ) $=
    ( wn wi wsb wo sbim sbn imbi1i bitr df-or bisb 3bitr4 ) AEZBFZCDGZACDGZEZBC
    DGZFZABHZCDGSUAHRPCDGZUAFUBPBCDIUDTUAACDJKLUCQCDABMNSUAMO $.
    $( [29-Sep-02] $)

  ${
    sb19.21.1 $e |- ( ph -> A. x ph ) $.
    $( Substitution with a variable not free in antecedent affects only the
       consequent. $)
    sb19.21 $p |- ( [ y / x ] ( ph -> ps ) <-> ( ph -> [ y / x ] ps ) ) $=
      ( wi wsb sbim sbf imbi1i bitr ) ABFCDGACDGZBCDGZFAMFABCDHLAMACDEIJK $.
      $( [5-Aug-93] $)
  $}

  $( Conjunction inside and outside of a substitution are equivalent. $)
  sban $p |- ( [ y / x ] ( ph /\ ps ) <-> ( [ y / x ] ph /\ [ y / x ] ps ) ) $=
    ( wn wi wsb wa sbn sbim imbi2i bitr negbii df-an bisb 3bitr4 ) ABEZFZEZCDGZ
    ACDGZBCDGZEZFZEZABHZCDGUAUBHTRCDGZEUERCDIUGUDUGUAQCDGZFUDAQCDJUHUCUABCDIKLM
    LUFSCDABNOUAUBNP $.
    $( [5-Aug-93] $)

  $( Equivalence inside and outside of a substitution are equivalent. $)
  sbbi $p |- ( [ y / x ] ( ph <-> ps ) <-> ( [ y / x ] ph <-> [ y / x ] ps ) )
             $=
    ( wb wsb wi wa bi bisb sbim anbi12i sban 3bitr4 bitr ) ABEZCDFABGZBAGZHZCDF
    ZACDFZBCDFZEZPSCDABIJQCDFZRCDFZHUAUBGZUBUAGZHTUCUDUFUEUGABCDKBACDKLQRCDMUAU
    BINO $.
    $( [5-Aug-93] $)

  ${
    sblbis.1 $e |- ( [ y / x ] ph <-> ps ) $.
    $( Introduce left biconditional inside of a substitution. $)
    sblbis $p |- ( [ y / x ] ( ch <-> ph ) <-> ( [ y / x ] ch <-> ps ) ) $=
      ( wb wsb sbbi bibi2i bitr ) CAGDEHCDEHZADEHZGLBGCADEIMBLFJK $.
      $( [19-Aug-93] $)
  $}

  ${
    sbrbis.1 $e |- ( [ y / x ] ph <-> ps ) $.
    $( Introduce right biconditional inside of a substitution. $)
    sbrbis $p |- ( [ y / x ] ( ph <-> ch ) <-> ( ps <-> [ y / x ] ch ) ) $=
      ( wb wsb sbbi bibi1i bitr ) ACGDEHADEHZCDEHZGBMGACDEILBMFJK $.
      $( [18-Aug-93] $)
  $}

  ${
    sbrbif.1 $e |- ( ch -> A. x ch ) $.
    sbrbif.2 $e |- ( [ y / x ] ph <-> ps ) $.
    $( Introduce right biconditional inside of a substitution. $)
    sbrbif $p |- ( [ y / x ] ( ph <-> ch ) <-> ( ps <-> ch ) ) $=
      ( wb wsb sbrbis sbf bibi2i bitr ) ACHDEIBCDEIZHBCHABCDEGJNCBCDEFKLM $.
      $( [18-Aug-93] $)
  $}

  $( A specialization theorem. $)
  sbea4 $p |- ( [ y / x ] ph -> E. x ph ) $=
    ( wsb wn wal wex stdpc4 sbn sylib con2i df-ex sylibr ) ABCDZAEZBFZEABGPNPOB
    CDNEOBCHABCIJKABLM $.
    $( [5-Aug-93] $)

  $( Specialization of implication. $)
  sbia4 $p |- ( A. x ( ph -> ps ) -> ( [ y / x ] ph -> [ y / x ] ps ) ) $=
    ( wi wal wsb stdpc4 sbim sylib ) ABEZCFKCDGACDGBCDGEKCDHABCDIJ $.
    $( [5-Aug-93] $)

  $( Specialization of biconditional. $)
  sbba4 $p |- ( A. x ( ph <-> ps ) -> ( [ y / x ] ph <-> [ y / x ] ps ) ) $=
    ( wb wal wsb stdpc4 sbbi sylib ) ABEZCFKCDGACDGBCDGEKCDHABCDIJ $.
    $( [5-Aug-93] $)

  ${
    bisbd.1 $e |- ( ph -> A. x ph ) $.
    bisbd.2 $e |- ( ph -> ( ps <-> ch ) ) $.
    $( Deduction substituting both sides of a biconditional. $)
    bisbd $p |- ( ph -> ( [ y / x ] ps <-> [ y / x ] ch ) ) $=
      ( wb wal wsb 19.21ai sbba4 syl ) ABCHZDIBDEJCDEJHANDFGKBCDELM $.
      $( [5-Aug-93] $)
  $}

  $( Substitution does not change an identical variable specifier. $)
  sbequ5 $p |- ( [ w / z ] A. x x = y <-> A. x x = y ) $=
    ( weq wal hbae sbf ) ABEAFCDABCGH $.
    $( [21-Dec-04] $)


  ${
    sbt.1 $e |- ph $.
    $( A substitution into a theorem remains true.  (See ~ chvar and ~ chvarv for
       versions with implicit substitution. $)
    sbt $p |- [ y / x ] ph $=
      ( weq wi wsb sb2 a1i mpg ) BCEZAFABCGBABCHAKDIJ $.
      $( [21-Jan-04] $) $( [21-Jan-04] $)
  $}

  $( Substitution applied to atomic wff. $)
  equsb1 $p |- [ y / x ] x = y $=
    ( weq wi wsb sb2 id mpg ) ABCZIDIABEAIABFIGH $.
    $( [5-Aug-93] $)

  $( Substitution applied to atomic wff. $)
  equsb2 $p |- [ y / x ] y = x $=
    ( weq wi wsb sb2 equcomi mpg ) ABCBACZDIABEAIABFABGH $.
    $( [5-Aug-93] $)

  $( Elimination of equality from antecedent after substitution. $)
  sbequ8 $p |- ( [ y / x ] ph <-> [ y / x ] ( x = y -> ph ) ) $=
    ( wsb weq wi equsb1 a1bi sbim bitr4 ) ABCDZBCEZBCDZKFLAFBCDMKBCGHLABCIJ $.
    $( [5-Aug-93] $)

  ${
    sbied.1 $e |- ( ph -> A. x ph ) $.
    sbied.2 $e |- ( ph -> ( ch -> A. x ch ) ) $.
    sbied.3 $e |- ( ph -> ( x = y -> ( ps <-> ch ) ) ) $.
    $( Conversion of implicit substitution to explicit substitution (deduction
       version of ~ sbie ). $)
    sbied $p |- ( ph -> ( [ y / x ] ps <-> ch ) ) $=
      ( wsb wal wi wex weq wa wb bi1 syl6 imp3a 19.20i 19.22 syl sb1 syl5 hba1
      19.23 sylib ax-4 syld a4s bi2 com23 19.20ii sb2 impbid ) ABDEIZCAADJZUOCK
      FUPUOCDLZCUPDEMZBNZDLZUQUOUPUSCKZDJUTUQKAVADAURBCAURBCOZBCKHBCPQRSUSCDTUA
      BDEUBUCUPUQCDJZCUPCVCKZDJUQVCKAVDDGSCVCDCDUDUEUFCDUGQUHUAAUPCUOKFUPCVCUOA
      VDDGUIUPVCURBKZDJUOACVEDAURCBAURVBCBKHBCUJQUKULBDEUMQUHUAUN $.
      $( [30-Jun-94] $)
  $}

  ${
    sbie.1 $e |- ( ps -> A. x ps ) $.
    sbie.2 $e |- ( x = y -> ( ph <-> ps ) ) $.
    $( Conversion of implicit substitution to explicit substitution. $)
    sbie $p |- ( [ y / x ] ph <-> ps ) $=
      ( wi wsb wb id hbth wal a1i weq sbied ax-mp ) AAGZACDHBIAJZQABCDQCRKBBCLG
      QEMCDNABIGQFMOP $.
      $( [30-Jun-94] $)
  $}

  ${
    hbsb4.1 $e |- ( ph -> A. z ph ) $.
    $( A variable not free remains so after substitution with a distinct
       variable. $)
    hbsb4 $p |- ( -. A. z z = y -> ( [ y / x ] ph -> A. z [ y / x ] ph ) ) $=
      ( weq wal wn wsb wi ax-8 a4s alequcoms dral2OLD con3d hbsb2 ax-10 syl9r
      syld wa hbae ax-4 19.20i sbequ2 sbequ1 19.20ii syl5 3syl a1d sb4 hbnae
      hban ax-12 imp a1i hbimd 19.20d sb2 a7s syl6 syl9 pm2.61i exp ) DBFDGZDCF
      ZDGZHZABCIZVHDGZJZJVDVGBCFZBGZHZVJVDVLVFVKVEDBVKVEJZBDBDFVNBBDCKLMNOVMVHV
      HBGZVDVIABCPVOVIJBDVHBDQMRSVDHZVGVJVLVPVGTZVJJVLVJVQVLVLDGVKDGZVJBCDUAVLV
      KDVKBUBUCVRVHAVIVKVHAJDABCUDLVRADGZVIAVKAVHDABCUEUFEUGSUHUIVMVHVKAJZBGZVQ
      VIABCUJVQWAVTDGZBGVIVQVTWBBVPVGBDBBUKDCBUKULVQVKADVPVGDDBDUKDCDUKULVPVGVK
      VRJBCDUMUNAVSJVQEUOUPUQVTVIDBWAVHDABCURUCUSUTVAVBVCVB $.
      $( [5-Aug-93] $)
  $}

  $( A variable not free remains so after substitution with a distinct
     variable (closed form of ~ hbsb4 ). $)
  hbsb4t $p |- ( A. x A. z ( ph -> A. z ph ) ->
               ( -. A. z z = y -> ( [ y / x ] ph -> A. z [ y / x ] ph ) ) ) $=
    ( wal wi wsb weq wn wb wa ax-4 biantru bi bitr4 bi2al sbba4 a4s hba1 biald
    imbi12d a7s sylbi hbsb4 syl5bir ) AADEZFZDEBEZABCGZUIDEZFZUFBCGZULDEZFZDCHD
    EIUHAUFJZDEBEUKUNJZUGUOBDUGUGUFAFZKUOUQUGADLMAUFNOPUOUPDBUOBEZDEZUIULUJUMUR
    UIULJDAUFBCQRZUSUIULDURDSUTTUAUBUCUFBCDADSUDUE $.
    $( [14-Apr-04] $) $( [7-Apr-04] $)

  ${
    ddelimf2.1 $e |- ( ph -> A. x ph ) $.
    ddelimf2.2 $e |- ( ps -> A. z ps ) $.
    ddelimf2.3 $e |- ( z = y -> ( ph <-> ps ) ) $.
    $( Proof of ~ dvelimf without using ~ ax-11 .  This may be useful in a
       study to determine whether ~ ax-11 can be derived from the others,
       which is currently unknown. $)
    dvelimf2 $p |- ( -. A. x x = y -> ( ps -> A. x ps ) ) $=
      ( weq wal wn wi ax-10 alequcoms hba1 syl5 a1d wa hbnae hban ax-12 imp
      a1i hbimd hbald exp pm2.61i equsal bial 3imtr3g ) CDICJKZEDIZALZEJZUNCJZB
      BCJCEICJZUKUNUOLZLUPUQUKUPUNEJZUOUNURUOLECUNECMNUMEOPQUPKZUKUQUSUKRZUMCEU
      SUKECEESCDESTUTULACUSUKCCECSCDCSTUSUKULULCJLEDCUAUBAACJLUTFUCUDUEUFUGABED
      GHUHZUNBCVAUIUJ $.
      $( [12-Nov-02] $)
  $}

  ${
    ddelimf.1 $e |- ( ph -> A. x ph ) $.
    ddelimf.2 $e |- ( ps -> A. z ps ) $.
    ddelimf.3 $e |- ( z = y -> ( ph <-> ps ) ) $.
    $( Version of ~ dvelim without any variable restrictions. $)
    dvelimf $p |- ( -. A. x x = y -> ( ps -> A. x ps ) ) $=
      ( weq wal wn wsb hbsb4 sbie bial 3imtr3g ) CDICJKAEDLZQCJBBCJAEDCFMABEDGH
      NZQBCROP $.
      $( [1-Oct-02] $)
  $}

  ${
    ddelimdf.1 $e |- ( ph -> A. x ph ) $.
    ddelimdf.2 $e |- ( ph -> A. z ph ) $.
    ddelimdf.3 $e |- ( ph -> ( ps -> A. x ps ) ) $.
    ddelimdf.4 $e |- ( ph -> ( ch -> A. z ch ) ) $.
    ddelimdf.5 $e |- ( ph -> ( z = y -> ( ps <-> ch ) ) ) $.
    $( Deduction form of ~ dvelimf .  This version may be useful if we want to
       avoid ~ ax-17 and use ~ ax-16 instead. $)
    dvelimdf $p |- ( ph -> ( -. A. x x = y -> ( ch -> A. x ch ) ) ) $=
      ( weq wal wn wi wa wsb 19.21ai 19.20i2 hbsb4t 3syl imp wb sbied adantr
      biald 3imtr3d exp ) ADELDMNZCCDMZOAUIPBFEQZUKDMZCUJAUIUKULOZAADMZFMBBDMOZ
      DMFMUIUMOAUNFHGRAUOFDISBFEDTUAUBAUKCUCUIABCFEHJKUDZUEAULUJUCUIAUKCDGUPUFU
      EUGUH $.
      $( [15-Apr-04] $) $( [7-Apr-04] $)
  $}

  $( A composition law for substitution. $)
  sbco $p |- ( [ y / x ] [ x / y ] ph <-> [ y / x ] ph ) $=
    ( wsb wb weq equsb2 sbequ12 bicomd sbimi ax-mp sbbi mpbi ) ACBDZAEZBCDZNBCD
    ABCDECBFZBCDPBCGQOBCQANACBHIJKNABCLM $.
    $( [5-Aug-93] $)

  ${
    sbid2.1 $e |- ( ph -> A. x ph ) $.
    $( An identity law for substitution. $)
    sbid2 $p |- ( [ y / x ] [ x / y ] ph <-> ph ) $=
      ( wsb sbco sbf bitr ) ACBEBCEABCEAABCFABCDGH $.
      $( [5-Aug-93] $)
  $}

  $( An idempotent law for substitution. $)
  sbidm $p |- ( [ y / x ] [ y / x ] ph <-> [ y / x ] ph ) $=
    ( weq wal wsb wb sbequ12 bicomd a4s wn hbnae hbsb2 wi pm4.2i a1i sbied
    pm2.61i ) BCDZBEZABCFZBCFZUAGZSUCBSUAUBUABCHIJTKZUAUABCBCBLABCMSUAUAGNUDSUA
    OPQR $.
    $( [30-Jun-94] $)

  ${
    sbco2.1 $e |- ( ph -> A. z ph ) $.
    $( A composition law for substitution. $)
    sbco2 $p |- ( [ y / z ] [ z / x ] ph <-> [ y / x ] ph ) $=
      ( weq wal wsb wb sbequ sbid2 syl5bbr sbequ12 bitr3d a4s wn hbnae hbsb3
      hbsb4 wi a1i sbied bicomd pm2.61i ) BCFZBGZABDHZDCHZABCHZIZUEUJBUEAUHUIUE
      UGDBHUHAUGBCDJADBEKLZABCMNOUFPZUIUHULAUHBCBCBQUGDCBABDERSUEAUHITULUKUAUBU
      CUD $.
      $( [30-Jun-94] $)
  $}

  ${
    sbco2d.1 $e |- ( ph -> A. x ph ) $.
    sbco2d.2 $e |- ( ph -> A. z ph ) $.
    sbco2d.3 $e |- ( ph -> ( ps -> A. z ps ) ) $.
    $( A composition law for substitution. $)
    sbco2d $p |- ( ph -> ( [ y / z ] [ z / x ] ps <-> [ y / x ] ps ) ) $=
      ( wsb wi hbim1 sbco2 sb19.21 bisb bitr 3bitr3 pm5.74ri ) ABCEIZEDIZBCDIZA
      BJZCEIZEDIZUACDIASJZATJUACDEABEGHKLUCARJZEDIUDUBUEEDABCEFMNAREDGMOABCDFMP
      Q $.
      $( [5-Aug-93] $)
  $}

  $( A composition law for substitution. $)
  sbco3 $p |- ( [ z / y ] [ y / x ] ph <-> [ z / x ] [ x / y ] ph ) $=
    ( weq wal wsb wb drsb1 sbequ12a 19.20i sbba4 syl bitr3d wn hbnae hbsb2
    sbco2d sbco bisb syl5rbbr pm2.61i ) BCEZBFZABCGZCDGZACBGZBDGZHUDUEBDGZUFUHU
    EBCDIUDUEUGHZBFUIUHHUCUJBABCJKUEUGBDLMNUDOZUECBGZBDGUFUHUKUECDBBCCPBCBPABCQ
    RULUGBDACBSTUAUB $.
    $( [5-Aug-93] $)

  $( A commutativity law for substitution. $)
  sbcom $p |- ( [ y / z ] [ y / x ] ph <-> [ y / x ] [ y / z ] ph ) $=
    ( weq wal wsb wb wn wa drsb1 hbae bisbd bitr3d adantr wi hbnae hban ax-12
    imp 19.20i 19.21g 3syl biald adantrr nalequcoms bi2.04 bial syl5bb alcom
    adantrl sb4b imbi2d sylan9bbr adantl sylan9bb 3bitr4d pm2.61an1 exp
    sbequ12 a4s pm2.61ii ) BCEZBFZDCEZDFZABCGZDCGZADCGZBCGZHZVDIZVFIZVKBDEBFZVL
    VMJZVKVNVKVOVNVGBCGVHVJVGBDCKVNVGVIBCBDBLABDCKMNOVNIZVOJZVEVCAPZBFZPZDFZVCV
    EAPZDFZPZBFZVHVJVQVEVRPZBFZDFZWAWEVPVLWHWAHVMVPVLJZWGVTDVPVLDBDDQZBCDQZRWIW
    IBFVEVEBFPZBFWGVTHVPVLBBDBQZBCBQRWIWLBVPVLWLDCBSTUAVEVRBUBUCUDUEVPVMWHWEHVL
    VPVMJZWFDFZBFWEWHWNWOWDBVPVMBWMDCBQZRWNVCWBPZDFZWDWOWNWNDFVCVCDFPZDFWRWDHVP
    VMDWJDCDQRWNWSDVPVMWSVMWSPDBBCDSUFTUAVCWBDUBUCWFWQDVEVCAUGUHUIUDWFDBUJUIUKN
    VOVHWAHVPVMVHVEVGPZDFVLWAVGDCULVLWTVTDWKVLVGVSVEABCULUMUDUNUOVOVJWEHVPVLVJV
    CVIPZBFVMWEVIBCULVMXAWDBWPVMVIWCVCADCULUMUDUPUOUQURUSVDVIVHVJVDAVGDCBCDLVCA
    VGHBABCUTVAMVCVIVJHBVIBCUTVANVFVGVHVJVEVGVHHDVGDCUTVAVFAVIBCDCBLVEAVIHDADCU
    TVAMNVB $.
    $( [27-May-97] $)

  ${
    sb5rf.1 $e |- ( ph -> A. y ph ) $.
    $( Reversed substitution. $)
    sb5rf $p |- ( ph <-> E. y ( y = x /\ [ y / x ] ph ) ) $=
      ( weq wsb wa wex sbid2 sb1 sylbir sbequ12r biimpa 19.23ai impbi ) ACBEZAB
      CFZGZCHZAQCBFSACBDIQCBJKRACDPQAACBLMNO $.
      $( [22-Mar-05] $) $( [3-Feb-05] $)

    $( Reversed substitution. $)
    sb6rf $p |- ( ph <-> A. y ( y = x -> [ y / x ] ph ) ) $=
      ( weq wsb wi wal sbequ1 equcoms com12 19.21ai sb2 sbco sylib sbf impbi )
      ACBEZABCFZGZCHZATCDRASASGBCABCIJKLUAACBFZAUASCBFUBSCBMACBNOACBDPOQ $.
      $( [5-Aug-93] $)
  $}

  ${
    sb8.1 $e |- ( ph -> A. y ph ) $.
    $( Substitution of variable in universal quantifier. $)
    sb8 $p |- ( A. x ph <-> A. y [ y / x ] ph ) $=
      ( wal wsb hbal stdpc4 19.21ai hbsb3 sbid2 sylib impbi ) ABEZABCFZCEZNOCAC
      BDGABCHIPABOBCABCDJGPOCBFAOCBHACBDKLIM $.
      $( [5-Aug-93] $)
  $}

  ${
    sb8e.1 $e |- ( ph -> A. y ph ) $.
    $( Substitution of variable in existential quantifier. $)
    sb8e $p |- ( E. x ph <-> E. y [ y / x ] ph ) $=
      ( wn wal wsb wex hbne sb8 sbn bial bitr negbii df-ex 3bitr4 ) AEZBFZEABCG
      ZEZCFZEABHSCHRUARQBCGZCFUAQBCACDIJUBTCABCKLMNABOSCOP $.
      $( [12-Aug-93] $)
  $}

  $( Commutation of quantification and substitution variables. $)
  sb9i $p |- ( A. x [ x / y ] ph -> A. y [ y / x ] ph ) $=
    ( weq wal wsb wi drsb1OLD drsb3OLD syld dral2OLD wn hbsb2 19.20ii hbnaes stdpc4
    sbco sylib 19.20i a7s syl6 pm2.61i ) CBDCEZACBFZBEZABCFZCEZGUDUFCBUCUDABBFU
    FACBBHACBBIJKUCLZUEUDCEZBEZUGUEUJGCBBUHUDUIBACBMNOUDUGCBUEUFCUEUDBCFUFUDBCP
    ABCQRSTUAUB $.
    $( [5-Aug-93] $)

  $( Commutation of quantification and substitution variables. $)
  sb9 $p |- ( A. x [ x / y ] ph <-> A. y [ y / x ] ph ) $=
    ( wsb wal sb9i impbi ) ACBDBEABCDCEABCFACBFG $.
    $( [5-Aug-93] $)

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        The axioms of distinct variables and quantifier introduction.
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  ${
    $d x y $.
    $( Axiom of Distinct Variables.  The only axiom of predicate calculus
       requiring that variables be distinct (if we consider ~ ax-17 below to be
       a metatheorem and not an axiom).  Axiom scheme C16' in [Megill]
       p. 448 (p. 16 of the preprint).    It apparently does not otherwise
       appear in the literature but is easily proved from textbook predicate
       calculus by cases.  It is a somewhat bizarre axiom since the antecedent
       is always false in set theory (see ~ dtru ) but nonetheless technically
       necessary as you can see from its uses. $)
    ax-16 $a |- ( A. x x = y -> ( ph -> A. x ph ) ) $.
  $}



  ${
    $d x z $. $d y z $.
    $( Theorem to add distinct quantifier to atomic formula. $)
    ax17eq $p |- ( x = y -> A. z x = y ) $=
      ( weq wal wi ax-12 ax-16 pm2.61ii ) CADCECBDCEABDZJCEFABCGJCAHJCBHI $.
      $( [5-Aug-93] $)
  $}
