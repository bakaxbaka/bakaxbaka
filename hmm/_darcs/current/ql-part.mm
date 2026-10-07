$(
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
     Metamath source file for quantum logic
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
$)

$(

ql.mm - Version of 9-Jul-05

                             PUBLIC DOMAIN

This file (specifically, the version of this file with the above date)
is placed in the public domain per the Creative Commons Public Domain
Dedication. http://creativecommons.org/licenses/publicdomain/

Norman Megill - email: nm(at)alum(dot)mit(dot)edu

$)

$(
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
        AUQL - Algebraic Unified Quantum Logic of M. Pavicic
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
$)

  $( Declare the primitive constant symbols. $)
  $c ( $.  $( Left parenthesis $)
  $c ) $.  $( Right parenthesis $)
  $c = $. $( Equality (read:  'equals') $)
  $c == $. $( Biconditional (read:  'equivalent') $)
  $c v $. $( Disjunction (read:  'or') $)
  $c ^ $. $( Conjuction (read:  'and') $)
  $c 1 $. $( True constant (upside down ' ) (read:  'true') $)
  $c 0 $. $( False constant ( ' ) (read:  'false') $)
  $c ' $. $( Orthocomplement $)
  $c wff $. $( Well-formed formula symbol (read:  'the following symbol
               sequence is a wff') $)
  $c term $. $( Term $)
  $c |- $. $( Turnstile (read:  'the following symbol sequence is provable' or
              'a proof exists for') $)

  $( Relations as operations $)
  $c C $. $( Commutes relation or commutator operation $)
  $c =<  $.  $( Less-than-or-equal-to $)
  $c =<2  $.  $( Less-than-or-equal-to analogue for terms $)
  $c ->0 $. $( Right arrow (read:  'implies') $)
  $c ->1 $. $( Right arrow (read:  'implies') $)
  $c ->2 $. $( Right arrow (read:  'implies') $)
  $c ->3 $. $( Right arrow (read:  'implies') $)
  $c ->4 $. $( Right arrow (read:  'implies') $)
  $c ->5 $. $( Right arrow (read:  'implies') $)
  $c ==0 $. $( Classical identity $)
  $c ==1 $. $( Asymmetrical identity $)
  $c ==2 $. $( Asymmetrical identity $)
  $c ==3 $. $( Asymmetrical identity $)
  $c ==4 $. $( Asymmetrical identity $)
  $c ==5 $. $( Asymmetrical identity $)
  $c ==OA $. $( Orthoarguesian identity $)
  $c , $.  $( Comma $)
  $c <->3 $. $( Biconditional (read:  'equivalent') $)
  $c <->1 $. $( Biconditional (read:  'equivalent') $)
  $c u3 $. $( Disjunction (read:  'or') $)
  $c ^3 $. $( Conjuction (read:  'and') $)

  $( Introduce some variable names we will use to terms. $)
  $v a $.
  $v b $.
  $v c $.
  $v d $.
  $v e $.
  $v f $.
  $v g $.
  $v h $.
  $v j $.
  $v k $.
  $v l $.

  $v i $.
  $v m $.
  $v n $.
  $v p $.
  $v q $.
  $v r $.
  $v t $.
  $v u $.
  $v w $.
  $v x $.
  $v y $.
  $v z $.

  $(
     Specify some variables that we will use to represent terms.
     The fact that a variable represents a wff is relevant only to a theorem
     referring to that variable, so we may use $f hypotheses.  The symbol
     ` term ` specifies that the variable that follows it represents a term.
  $)

  $( Let variable ` a ` be a term. $)
  wva   $f term a $.
  $( Let variable ` b ` be a term. $)
  wvb   $f term b $.
  $( Let variable ` c ` be a term. $)
  wvc   $f term c $.
  $( Let variable ` d ` be a term. $)
  wvd   $f term d $.
  $( Let variable ` e ` be a term. $)
  wve   $f term e $.
  $( Let variable ` f ` be a term. $)
  wvf   $f term f $.
  $( Let variable ` g ` be a term. $)
  wvg   $f term g $.
  $( Let variable ` h ` be a term. $)
  wvh   $f term h $.
  $( Let variable ` j ` be a term. $)
  wvj   $f term j $.
  $( Let variable ` k ` be a term. $)
  wvk   $f term k $.
  $( Let variable ` l ` be a term. $)
  wvl   $f term l $.

  $( Let variable ` i ` be a term. $)
  wvi   $f term i $.
  $( Let variable ` m ` be a term. $)
  wvm   $f term m $.
  $( Let variable ` n ` be a term. $)
  wvn   $f term n $.
  $( Let variable ` p ` be a term. $)
  wvp   $f term p $.
  $( Let variable ` q ` be a term. $)
  wvq   $f term q $.
  $( Let variable ` r ` be a term. $)
  wvr   $f term r $.
  $( Let variable ` t ` be a term. $)
  wvt   $f term t $.
  $( Let variable ` u ` be a term. $)
  wvu   $f term u $.
  $( Let variable ` w ` be a term. $)
  wvw   $f term w $.
  $( Let variable ` x ` be a term. $)
  wvx   $f term x $.
  $( Let variable ` y ` be a term. $)
  wvy   $f term y $.
  $( Let variable ` z ` be a term. $)
  wvz   $f term z $.

  $(
     Recursively define terms and wffs.
  $)

  $( If ` a ` and ` b ` are terms, ` a = b ` is a wff. $)
  wb $a wff a = b $.
  $( If ` a ` and ` b ` are terms, ` a =< b ` is a wff. $)
  wle $a wff a =< b $.
  $( If ` a ` and ` b ` are terms, ` a C b ` is a wff. $)
  wc $a wff a C b $.


  $( If ` a ` is a term, ` a ' ` is a wff. $)
  wn $a term a ' $.
  $( If ` a ` and ` b ` are terms, so is ` ( a == b ) ` . $)
  tb $a term ( a == b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a v b ) ` . $)
  wo $a term ( a v b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ^ b ) ` . $)
  wa $a term ( a ^ b ) $.
$(
  @( If ` a ` and ` b ` are terms, so is ` ( a ' b ) ` . @)
  wp @a term ( a ' b ) @.
$)
  $( The logical true constant is a term. $)
  wt $a term 1 $.
  $( The logical false constant is a term. $)
  wf $a term 0 $.
  $( If ` a ` and ` b ` are terms, so is ` ( a =<2 b ) ` . $)
  wle2 $a term ( a =<2 b ) $.

  $( If ` a ` and ` b ` are terms, so is ` ( a ->0 b ) ` . $)
  wi0 $a term ( a ->0 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ->1 b ) ` . $)
  wi1 $a term ( a ->1 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ->2 b ) ` . $)
  wi2 $a term ( a ->2 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ->3 b ) ` . $)
  wi3 $a term ( a ->3 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ->4 b ) ` . $)
  wi4 $a term ( a ->4 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ->5 b ) ` . $)
  wi5 $a term ( a ->5 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ==0 b ) ` . $)
  wid0 $a term ( a ==0 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ==1 b ) ` . $)
  wid1 $a term ( a ==1 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ==2 b ) ` . $)
  wid2 $a term ( a ==2 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ==3 b ) ` . $)
  wid3 $a term ( a ==3 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ==4 b ) ` . $)
  wid4 $a term ( a ==4 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ==5 b ) ` . $)
  wid5 $a term ( a ==5 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a <->3 b ) ` . $)
  wb3 $a term ( a <->3 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a <->3 b ) ` . $)
  wb1 $a term ( a <->1 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a u3 b ) ` . $)
  wo3 $a term ( a u3 b ) $.
  $( If ` a ` and ` b ` are terms, so is ` ( a ^3 b ) ` . $)
  wan3 $a term ( a ^3 b ) $.
  $( If ` a `, ` b ` , and ` c ` are terms, so is ` ( a == c ==OA b ) ` . $)
  wid3oa $a term ( a == c ==OA b ) $.
  $( If ` a `, ` b ` , ` c ` , and ` d ` are terms, so is
   ` ( a == c , d ==OA b ) ` . $)
  wid4oa $a term ( a == c , d ==OA b ) $.
  $( If ` a ` and ` b ` are terms, so is ` C ( a , b ) ` . $)
  wcmtr $a term C ( a , b ) $.

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        The axioms of orthomodular lattices
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( Axiom for ortholattices. $)
  ax-a1 $a |- a = a ' '  $.

  $( Axiom for ortholattices. $)
  ax-a2 $a |- ( a v b ) = ( b v a ) $.

  $( Axiom for ortholattices. $)
  ax-a3 $a |- ( ( a v b ) v c ) = ( a v ( b v c ) ) $.

  $( Axiom for ortholattices. $)
  ax-a4 $a |- ( a v ( b v b ' ) ) = ( b v b ' ) $.

  $(
  ax-a5 $a |- ( a v ( a ' v b ' ) ' ) = a $.
  $)

  $( Axiom for ortholattices. $)
  ax-a5 $a |- ( a v ( a ' v b ) ' ) = a $.

  $(
  df-b $a |- ( a == b ) =
           ( ( a ' ' v b ' ' ) ' v ( a ' v b ' ) ' ) $.
  $)


  ${
    r1.1 $e |- a = b $.
    $( Inference rule for ortholattices. $)
    ax-r1 $a |- b = a $.
  $}

  ${
    r2.1 $e |- a = b $.
    r2.2 $e |- b = c $.
    $( Inference rule for ortholattices. $)
    ax-r2 $a |- a = c $.
  $}

  $( Axiom ~ax-r3 is the orthomodular axiom and will be introduced
     when we start to use it. $)
  ${
    r4.1 $e |- a = b $.
    $( Inference rule for ortholattices. $)
    ax-r4 $a |- a ' = b ' $.
  $}

  ${
    r5.1 $e |- a = b $.
    $( Inference rule for ortholattices. $)
    ax-r5 $a |- ( a v c ) = ( b v c ) $.
  $}

  $( Define biconditional. $)
  df-b $a |- ( a == b ) = ( ( a ' v  b ' ) ' v ( a v b ) ' ) $.

  $( Define conjunction. $)
  df-a $a |- ( a ^ b ) = ( a ' v b ' ) ' $.

  $( Define true. $)
  df-t $a |- 1 = ( a v a ' ) $.

  $( Define false. $)
  df-f $a |- 0 = 1 ' $.

  $( Define classical conditional. $)
  df-i0 $a |- ( a ->0 b ) = ( a ' v b ) $.

  $( Define Sasaki (Mittelstaedt) conditional. $)
  df-i1 $a |- ( a ->1 b ) = ( a ' v ( a ^ b ) ) $.

  $( Define Dishkant conditional. $)
  df-i2 $a |- ( a ->2 b ) = ( b v ( a ' ^ b ' ) ) $.

  $( Define Kalmbach conditional. $)
  df-i3 $a |- ( a ->3 b ) = ( ( ( a ' ^ b ) v ( a ' ^ b ' ) ) v
                ( a ^ ( a ' v b ) ) ) $.

  $( Define non-tollens conditional. $)
  df-i4 $a |- ( a ->4 b ) = ( ( ( a ^ b ) v ( a ' ^ b ) ) v
                ( ( a ' v b ) ^ b ' ) ) $.

  $( Define relevance conditional. $)
  df-i5 $a |- ( a ->5 b ) = ( ( ( a ^ b ) v ( a ' ^ b ) ) v
                ( a ' ^ b ' ) ) $.

  $( Define classical identity. $)
  df-id0 $a |- ( a ==0 b ) = ( ( a ' v b ) ^ ( b ' v a ) ) $.

  $( Define asymmetrical identity (for "Non-Orthomodular Models..." paper). $)
  df-id1 $a |- ( a ==1 b ) = ( ( a v b ' ) ^ ( a ' v ( a ^ b ) ) ) $.

  $( Define asymmetrical identity (for "Non-Orthomodular Models..." paper). $)
  df-id2 $a |- ( a ==2 b ) = ( ( a v b ' ) ^ ( b v ( a ' ^ b ' ) ) ) $.

  $( Define asymmetrical identity (for "Non-Orthomodular Models..." paper). $)
  df-id3 $a |- ( a ==3 b ) = ( ( a ' v b ) ^ ( a v ( a ' ^ b ' ) ) ) $.

  $( Define asymmetrical identity (for "Non-Orthomodular Models..." paper). $)
  df-id4 $a |- ( a ==4 b ) = ( ( a ' v b ) ^ ( b ' v ( a ^ b ) ) ) $.

  $( Defined disjunction. $)
  df-o3 $a |- ( a u3 b ) = ( a ' ->3 ( a ' ->3 b ) ) $.

  $( Defined conjunction. $)
  df-a3 $a |- ( a ^3 b ) = ( a ' u3 b ' ) ' $.

  $( Defined biconditional. $)
  df-b3 $a |- ( a <->3 b ) = ( ( a ->3 b ) ^ ( b ->3 a ) ) $.

  $( The 3-variable orthoarguesian identity term. $)
  df-id3oa $a |- ( a == c ==OA b ) = ( ( ( a ->1 c ) ^ ( b ->1 c ) )
     v ( ( a ' ->1 c ) ^ ( b ' ->1 c ) ) ) $.

  $( The 4-variable orthoarguesian identity term. $)
  df-id4oa $a |- ( a == c , d ==OA b ) =  ( ( a == d ==OA b ) v
                    ( ( a == d ==OA c ) ^ ( b == d ==OA c ) ) ) $.

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Basic lemmas
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( Identity law. $)
  id $p |- a = a $=
    ( wn ax-a1 ax-r1 ax-r2 ) AABBZAACZAFGDE $.
    $( [9-Aug-97] $)

  $( Justification of definition ~df-t of true ( ` 1 ` ).  This shows
     that the definition is independent of the variable used to define it. $)
  tt $p |- ( a v a ' ) = ( b v b ' ) $=
    ( wn wo ax-a4 ax-r1 ax-a2 ax-r2 ) AACDZIBBCDZDZJIJIDZKLIJAEFJIGHIBEH $.
    $( [9-Aug-97] $)


  ${
    3tr1.1 $e |- a = b $.
    3tr1.2 $e |- c = a $.
    3tr1.3 $e |- d = b $.
    $( Transitive inference useful for introducing definitions. $)
    3tr1 $p |- c = d $=
      ( ax-r1 ax-r2 ) CADFABDEDBGHII $.
      $( [10-Aug-97] $)
  $}

  ${
    3tr2.1 $e |- a = b $.
    3tr2.2 $e |- a = c $.
    3tr2.3 $e |- b = d $.
    $( Transitive inference useful for eliminating definitions. $)
    3tr2 $p |- c = d $=
      ( ax-r1 3tr1 ) ABCDEACFHBDGHI $.
      $( [10-Aug-97] $)
  $}

  ${
    3tr.1 $e |- a = b $.
    3tr.2 $e |- b = c $.
    3tr.3 $e |- c = d $.
    $( Triple transitive inference. $)
    3tr $p |- a = d $=
      ( ax-r2 ) ACDABCEFHGH $.
      $( [20-Sep-98] $)
  $}

  ${
    con1.1 $e |- a ' = b ' $.
    $( Contraposition inference. $)
    con1 $p |- a = b $=
      ( wn ax-r4 ax-a1 3tr1 ) ADZDBDZDABHICEAFBFG $.
      $( [10-Aug-97] $)
  $}

  ${
    con2.1 $e |- a = b ' $.
    $( Contraposition inference. $)
    con2 $p |- a ' = b $=
      ( wn ax-r4 ax-a1 ax-r1 ax-r2 ) ADBDZDZBAICEBJBFGH $.
      $( [10-Aug-97] $)
  $}

  ${
    con3.1 $e |- a ' = b $.
    $( Contraposition inference. $)
    con3 $p |- a = b ' $=
      ( wn ax-a1 ax-r4 ax-r2 ) AADZDBDAEHBCFG $.
      $( [10-Aug-97] $)
  $}

  ${
    lor.1 $e |- a = b $.
    $( Inference introducing disjunct to left. $)
    lor $p |- ( c v a ) = ( c v b ) $=
      ( wo ax-r5 ax-a2 3tr1 ) ACEBCECAECBEABCDFCAGCBGH $.
      $( [10-Aug-97] $)
  $}

  ${
    2or.1 $e |- a = b $.
    2or.2 $e |- c = d $.
    $( Join both sides with disjunction. $)
    2or $p |- ( a v c ) = ( b v d ) $=
      ( wo lor ax-r5 ax-r2 ) ACGADGBDGCDAFHABDEIJ $.
      $( [10-Aug-97] $)
  $}

  $( Commutative law. $)
  ancom $p |- ( a ^ b ) = ( b ^ a ) $=
    ( wn wo wa ax-a2 ax-r4 df-a 3tr1 ) ACZBCZDZCKJDZCABEBAELMJKFGABHBAHI $.
    $( [10-Aug-97] $)

  $( Associative law. $)
  anass $p |- ( ( a ^ b ) ^ c ) = ( a ^ ( b ^ c ) ) $=
    ( wa wn wo ax-a3 df-a con2 ax-r5 lor 3tr1 ax-r4 ) ABDZEZCEZFZEAEZBCDZEZFZEN
    CDASDQUARBEZFZPFRUBPFZFQUARUBPGOUCPNUCABHIJTUDRSUDBCHIKLMNCHASHL $.
    $( [12-Aug-97] $)

  ${
    lan.1 $e |- a = b $.
    $( Introduce conjunct on left. $)
    lan $p |- ( c ^ a ) = ( c ^ b ) $=
      ( wn wo wa ax-r4 lor df-a 3tr1 ) CEZAEZFZELBEZFZECAGCBGNPMOLABDHIHCAJCBJK
      $.
      $( [10-Aug-97] $)
  $}

  ${
    ran.1 $e |- a = b $.
    $( Introduce conjunct on right. $)
    ran $p |- ( a ^ c ) = ( b ^ c ) $=
      ( wa lan ancom 3tr1 ) CAECBEACEBCEABCDFACGBCGH $.
      $( [10-Aug-97] $)
  $}

  ${
    2an.1 $e |- a = b $.
    2an.2 $e |- c = d $.
    $( Conjoin both sides of hypotheses. $)
    2an $p |- ( a ^ c ) = ( b ^ d ) $=
      ( wa lan ran ax-r2 ) ACGADGBDGCDAFHABDEIJ $.
      $( [10-Aug-97] $)
  $}

  $( Swap disjuncts. $)
  or12 $p |- ( a v ( b v c ) ) = ( b v ( a v c ) ) $=
    ( wo ax-a2 ax-r5 ax-a3 3tr2 ) ABDZCDBADZCDABCDDBACDDIJCABEFABCGBACGH $.
    $( [27-Aug-97] $)

  $( Swap conjuncts. $)
  an12 $p |- ( a ^ ( b ^ c ) ) = ( b ^ ( a ^ c ) ) $=
    ( wa ancom ran anass 3tr2 ) ABDZCDBADZCDABCDDBACDDIJCABEFABCGBACGH $.
    $( [27-Aug-97] $)

  $( Swap disjuncts. $)
  or32 $p |- ( ( a v b ) v c ) = ( ( a v c ) v b ) $=
    ( wo ax-a2 lor ax-a3 3tr1 ) ABCDZDACBDZDABDCDACDBDIJABCEFABCGACBGH $.
    $( [27-Aug-97] $)

  $( Swap conjuncts. $)
  an32 $p |- ( ( a ^ b ) ^ c ) = ( ( a ^ c ) ^ b ) $=
    ( wa ancom lan anass 3tr1 ) ABCDZDACBDZDABDCDACDBDIJABCEFABCGACBGH $.
    $( [27-Aug-97] $)

  $( Swap disjuncts. $)
  or4 $p |- ( ( a v b ) v ( c v d ) ) = ( ( a v c ) v ( b v d ) ) $=
    ( wo or12 lor ax-a3 3tr1 ) ABCDEZEZEACBDEZEZEABEJEACELEKMABCDFGABJHACLHI $.
    $( [27-Aug-97] $)

  $( Swap conjuncts. $)
  an4 $p |- ( ( a ^ b ) ^ ( c ^ d ) ) = ( ( a ^ c ) ^ ( b ^ d ) ) $=
    ( wa an12 lan anass 3tr1 ) ABCDEZEZEACBDEZEZEABEJEACELEKMABCDFGABJHACLHI $.
    $( [27-Aug-97] $)

  $( Disjunction expressed with conjunction. $)
  oran $p |- ( a v b ) = ( a ' ^ b ' ) ' $=
    ( wn wo wa ax-a1 2or df-a ax-r4 3tr1 ) ACZCZBCZCZDZOCZCABDKMEZCOFALBNAFBFGQ
    PKMHIJ $.
    $( [10-Aug-97] $)

  $( Conjunction expressed with disjunction. $)
  anor1 $p |- ( a ^ b ' ) = ( a ' v b ) ' $=
    ( wn wa wo df-a ax-a1 ax-r1 lor ax-r4 ax-r2 ) ABCZDACZLCZEZCMBEZCALFOPNBMBN
    BGHIJK $.
    $( [12-Aug-97] $)

  $( Conjunction expressed with disjunction. $)
  anor2 $p |- ( a ' ^ b ) = ( a v b ' ) ' $=
    ( wn wa wo df-a ax-a1 ax-r1 ax-r5 ax-r4 ax-r2 ) ACZBDLCZBCZEZCANEZCLBFOPMAN
    AMAGHIJK $.
    $( [12-Aug-97] $)

  $( Conjunction expressed with disjunction. $)
  anor3 $p |- ( a ' ^ b ' ) = ( a v b ) ' $=
    ( wn wa wo oran ax-r1 con3 ) ACBCDZABEZJICABFGH $.
    $( [15-Dec-97] $)

  $( Disjunction expressed with conjunction. $)
  oran1 $p |- ( a v b ' ) = ( a ' ^ b ) ' $=
    ( wn wo wa anor2 ax-r1 con3 ) ABCDZACBEZJICABFGH $.
    $( [15-Dec-97] $)

  $( Disjunction expressed with conjunction. $)
  oran2 $p |- ( a ' v b ) = ( a ^ b ' ) ' $=
    ( wn wo wa anor1 ax-r1 con3 ) ACBDZABCEZJICABFGH $.
    $( [15-Dec-97] $)

  $( Disjunction expressed with conjunction. $)
  oran3 $p |- ( a ' v b ' ) = ( a ^ b ) ' $=
    ( wn wo wa df-a ax-r1 con3 ) ACBCDZABEZJICABFGH $.
    $( [15-Dec-97] $)

  $( Biconditional expressed with others. $)
  dfb $p |- ( a == b ) = ( ( a ^ b ) v ( a ' ^ b ' ) ) $=
    ( tb wn wo wa df-b df-a ax-r1 oran con2 2or ax-r2 ) ABCADZBDZEDZABEZDZEABFZ
    NOFZEABGPSRTSPABHIQTABJKLM $.
    $( [10-Aug-97] $)

  $( Negated biconditional. $)
  dfnb $p |- ( a == b ) ' = ( ( a v b ) ^ ( a ' v b ' ) ) $=
    ( wa wn wo tb oran con2 ancom ax-r2 dfb ax-r4 df-a ax-r1 2an 3tr1 ) ABCZADZ
    BDZCZEZDZTDZQDZCZABFZDABEZRSEZCUBUDUCCZUEUAUIQTGHUDUCIJUFUAABKLUGUCUHUDABGU
    DUHQUHABMHNOP $.
    $( [30-Aug-97] $)

  $( Commutative law. $)
  bicom $p |- ( a == b ) = ( b == a ) $=
    ( wa wn wo tb ancom 2or dfb 3tr1 ) ABCZADZBDZCZEBACZMLCZEABFBAFKONPABGLMGHA
    BIBAIJ $.
    $( [10-Aug-97] $)

  ${
    lbi.1 $e |- a = b $.
    $( Introduce biconditional to the left. $)
    lbi $p |- ( c == a ) = ( c == b ) $=
      ( wa wn wo tb lan ax-r4 2or dfb 3tr1 ) CAEZCFZAFZEZGCBEZOBFZEZGCAHCBHNRQT
      ABCDIPSOABDJIKCALCBLM $.
      $( [10-Aug-97] $)
  $}

  ${
    rbi.1 $e |- a = b $.
    $( Introduce biconditional to the right. $)
    rbi $p |- ( a == c ) = ( b == c ) $=
      ( tb lbi bicom 3tr1 ) CAECBEACEBCEABCDFACGBCGH $.
      $( [10-Aug-97] $)
  $}

  ${
    2bi.1 $e |- a = b $.
    2bi.2 $e |- c = d $.
    $( Join both sides with biconditional. $)
    2bi $p |- ( a == c ) = ( b == d ) $=
      ( tb lbi rbi ax-r2 ) ACGADGBDGCDAFHABDEIJ $.
      $( [10-Aug-97] $)
  $}

  $( Alternate defintion of "false". $)
  dff2 $p |- 0 = ( a v a ' ) ' $=
    ( wf wt wn wo df-f df-t ax-r4 ax-r2 ) BCDAADEZDFCJAGHI $.
    $( [10-Aug-97] $)

  $( Alternate defintion of "false". $)
  dff $p |- 0 = ( a ^ a ' ) $=
    ( wf wn wo wa dff2 ancom anor2 ax-r2 ax-r1 ) BAACZDCZAKEZAFMLMKAELAKGAAHIJI
    $.
    $( [29-Aug-97] $)

  $( Disjunction with 0. $)
  or0 $p |- ( a v 0 ) = a $=
    ( wf wo wn dff2 ax-a2 ax-r4 ax-r2 lor ax-a5 ) ABCAADZACZDZCABMABAKCZDMAENLA
    KFGHIAAJH $.
    $( [10-Aug-97] $)

  $( Disjunction with 0. $)
  or0r $p |- ( 0 v a ) = a $=
    ( wf wo ax-a2 or0 ax-r2 ) BACABCABADAEF $.
    $( [26-Nov-97] $)

  $( Disjunction with 1. $)
  or1 $p |- ( a v 1 ) = 1 $=
    ( wt wo wn df-t lor ax-a4 ax-r2 ax-r1 ) ABCZAADCZBJAKCKBKAAEZFAAGHBKLIH $.
    $( [10-Aug-97] $)

  $( Disjunction with 1. $)
  or1r $p |- ( 1 v a ) = 1 $=
    ( wt wo ax-a2 or1 ax-r2 ) BACABCBBADAEF $.
    $( [26-Nov-97] $)

  $( Conjunction with 1. $)
  an1 $p |- ( a ^ 1 ) = a $=
    ( wt wa wn wo df-a wf df-f ax-r1 lor or0 ax-r2 con2 ) ABCADZBDZEZDAABFPAPNG
    ENOGNGOHIJNKLML $.
    $( [10-Aug-97] $)

  $( Conjunction with 1. $)
  an1r $p |- ( 1 ^ a ) = a $=
    ( wt wa ancom an1 ax-r2 ) BACABCABADAEF $.
    $( [26-Nov-97] $)

  $( Conjunction with 0. $)
  an0 $p |- ( a ^ 0 ) = 0 $=
    ( wf wa wn wo df-a wt or1 df-f con2 lor 3tr1 ax-r2 ) ABCADZBDZEZDBABFPBNGEG
    PONHOGNBGIJZKQLJM $.
    $( [10-Aug-97] $)

  $( Conjunction with 0. $)
  an0r $p |- ( 0 ^ a ) = 0 $=
    ( wf wa ancom an0 ax-r2 ) BACABCBBADAEF $.
    $( [26-Nov-97] $)

  $( Idempotent law. $)
  oridm $p |- ( a v a ) = a $=
    ( wo wn wf ax-a1 or0 ax-r1 ax-r4 ax-r2 lor ax-a5 ) AABAACZDBZCZBAANAALCNAEL
    MMLLFGHIJADKI $.
    $( [10-Aug-97] $)

  $( Idempotent law. $)
  anidm $p |- ( a ^ a ) = a $=
    ( wa wn wo df-a oridm con2 ax-r2 ) AABACZIDZCAAAEJAIFGH $.
    $( [10-Aug-97] $)

  $( Distribution of disjunction over disjunction. $)
  orordi $p |- ( a v ( b v c ) ) =
               ( ( a v b ) v ( a v c ) ) $=
    ( wo oridm ax-r1 ax-r5 or4 ax-r2 ) ABCDZDAADZJDABDACDDAKJKAAEFGAABCHI $.
    $( [27-Aug-97] $)

  $( Distribution of disjunction over disjunction. $)
  orordir $p |- ( ( a v b ) v c ) =
               ( ( a v c ) v ( b v c ) ) $=
    ( wo oridm ax-r1 lor or4 ax-r2 ) ABDZCDJCCDZDACDBCDDCKJKCCEFGABCCHI $.
    $( [27-Aug-97] $)

  $( Distribution of conjunction over conjunction. $)
  anandi $p |- ( a ^ ( b ^ c ) ) =
               ( ( a ^ b ) ^ ( a ^ c ) ) $=
    ( wa anidm ax-r1 ran an4 ax-r2 ) ABCDZDAADZJDABDACDDAKJKAAEFGAABCHI $.
    $( [27-Aug-97] $)

  $( Distribution of conjunction over conjunction. $)
  anandir $p |- ( ( a ^ b ) ^ c ) =
               ( ( a ^ c ) ^ ( b ^ c ) ) $=
    ( wa anidm ax-r1 lan an4 ax-r2 ) ABDZCDJCCDZDACDBCDDCKJKCCEFGABCCHI $.
    $( [27-Aug-97] $)

  $( Identity law. $)
  biid $p |- ( a == a ) = 1 $=
    ( wa wn wo tb wt anidm 2or dfb df-t 3tr1 ) AABZACZMBZDAMDAAEFLANMAGMGHAAIAJ
    K $.
    $( [10-Aug-97] $)

  $( Identity law. $)
  1b $p |- ( 1 == a ) = a $=
    ( wt tb wa wn wo dfb wf ancom df-f ax-r1 lan ax-r2 2or an1 an0 or0 ) BACBAD
    ZBEZAEZDZFZABAGUBAHFZAUBABDZTHDZFUCRUDUAUEBAIUATSDUESTISHTHSJKLMNUDAUEHAOTP
    NMAQMM $.
    $( [10-Aug-97] $)

  ${
    bi1.1 $e |- a = b $.
    $( Identity inference. $)
    bi1 $p |- ( a == b ) = 1 $=
      ( tb wt rbi biid ax-r2 ) ABDBBDEABBCFBGH $.
      $( [30-Aug-97] $)
  $}

  ${
    1bi.1 $e |- a = b $.
    $( Identity inference. $)
    1bi $p |- 1 = ( a == b ) $=
      ( tb wt bi1 ax-r1 ) ABDEABCFG $.
      $( [30-Aug-97] $)
  $}

  $( Absorption law. $)
  a5b $p |- ( a v ( a ^ b ) ) = a $=
    ( wa wo wn df-a lor ax-a5 ax-r2 ) AABCZDAAEBEZDEZDAJLAABFGAKHI $.
    $( [11-Aug-97] $)

  $( Absorption law. $)
  a5c $p |- ( a ^ ( a v b ) ) = a $=
    ( wo wa wn ax-a1 ax-r5 lan df-a ax-r2 ax-a5 con2 ) AABCZDZAEZOEZBCZECZEZANA
    QDSMQAAPBAFGHAQIJRAOBKLJ $.
    $( [11-Aug-97] $)

  $( Contraposition law. $)
  conb $p |- ( a == b ) = ( a ' == b ' ) $=
    ( wa wn wo tb ax-a2 ax-a1 2an lor ax-r2 dfb 3tr1 ) ABCZADZBDZCZEZQODZPDZCZE
    ZABFOPFRQNEUBNQGNUAQASBTAHBHIJKABLOPLM $.
    $( [10-Aug-97] $)

  ${
    leoa.1 $e |- ( a v c ) = b $.
    $( Relation between two methods of expressing "less than or equal to". $)
    leoa   $p |- ( a ^ b ) = a $=
      ( wa wo ax-r1 lan a5c ax-r2 ) ABEAACFZEABKAKBDGHACIJ $.
      $( [11-Aug-97] $)
  $}

  ${
    leao.1 $e |- ( c ^ b ) = a $.
    $( Relation between two methods of expressing "less than or equal to". $)
    leao   $p |- ( a v b ) = b $=
      ( wo wa ax-a2 ax-r1 ancom ax-r2 lor a5b ) ABEZBBCFZEZBMBAEOABGANBACBFZNPA
      DHNPBCIHJKJBCLJ $.
      $( [11-Aug-97] $)
  $}

  $( Mittelstaedt implication. $)
  mi $p |- ( ( a v b ) == b ) = ( b v ( a ' ^ b ' ) ) $=
    ( wo tb wa wn dfb ancom ax-a2 lan a5c ax-r2 oran con2 ran anass anidm 2or
    ) ABCZBDSBEZSFZBFZEZCBAFZUBEZCSBGTBUCUETBSEZBSBHUFBBACZEBSUGBABIJBAKLLUCUDU
    BUBEZEZUEUCUEUBEUIUAUEUBSUEABMNOUDUBUBPLUHUBUDUBQJLRL $.
    $( [12-Aug-97] $)

  $( Dishkant implication. $)
  di $p |- ( ( a ^ b ) == a ) = ( a ' v ( a ^ b ) ) $=
    ( wn wo tb wa conb ax-a1 ax-r1 rbi mi ax-r2 ancom df-a 2an lor 3tr1 ) BCZAC
    ZDZCZAEZSRCZSCZFZDZABFZAESUGDUBUACZSEZUFUAAGUITSEUFUHTSTUHTHIJRSKLLUGUAAUGB
    AFZUAABMZBANLJUGUESUGUJUEUKBUCAUDBHAHOLPQ $.
    $( [12-Aug-97] $)

  $( Lemma in proof of Th. 1 of Pavicic 1987. $)
  omlem1 $p |- ( ( a v ( a ' ^ ( a v b ) ) ) v ( a v b ) ) =
               ( a v b ) $=
    ( wn wo wa ax-a2 ax-a3 3tr1 ax-r2 ax-r1 oridm ax-r5 ancom 2or a5b 3tr2 ) AA
    CZABDZEZDZADBDZRADZSDZTRDZRUDRTDUAUCTRFTABGZRASGHUEUCRRQEZDRUBRSUFUBAADZBDZ
    RUHUBUHARDUBAABGARFIJUGABAKLIQRMNRQOIP $.
    $( [12-Aug-97] $)

  $( Lemma in proof of Th. 1 of Pavicic 1987. $)
  omlem2 $p |- ( ( a v b ) ' v ( a v ( a ' ^ ( a v b ) ) ) ) = 1 $=
    ( wo wn wa wt ax-a2 anor2 2or ax-a3 ax-r1 df-t 3tr1 ) ABCZDZACZADNEZCZAOCZS
    DZCOAQCCZFPSQTOAGANHIRUAOAQJKSLM $.
    $( [12-Aug-97] $)


$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Relationship analogues (ordering; commutation)
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( Define 'less than or equal to' analogue. $)
  df-le $a |- ( a =<2 b ) = ( ( a v b ) == b ) $.

  $( Since we don't have strong BMP in AUQL, we must add extra definitions
     to eliminate the middle = .  $)
  ${
    df-le1.1 $e |- ( a v b ) = b $.
    $( Define 'less than or equal to'.  See ~ df-le2 for the other direction. $)
    df-le1 $a |- a =< b $.
  $}

  ${
    df-le2.1 $e |- a =< b $.
    $( Define 'less than or equal to'.  See ~ df-le1 for the other direction. $)
    df-le2 $a |- ( a v b ) = b $.
  $}

  ${
    df-c1.1 $e |- a = ( ( a ^ b ) v ( a ^ b ' ) ) $.
    $( Define 'commutes'.  See ~ df-c2 for the other direction. $)
    df-c1 $a |- a C b $.
  $}

  ${
    df-c2.1 $e |- a C b $.
    $( Define 'commutes'.  See ~ df-c1 for the other direction. $)
    df-c2 $a |- a = ( ( a ^ b ) v ( a ^ b ' ) ) $.
  $}

  $( Define 'commutator'. $)
  df-cmtr $a |- C ( a , b ) = ( ( ( a ^ b ) v ( a ^ b ' ) ) v
             ( ( a ' ^ b ) v ( a ' ^ b ' ) ) ) $.

  ${
    df2le1.1 $e |- ( a ^ b ) = a $.
    $( Alternate definition of 'less than or equal to'. $)
    df2le1 $p |- a =< b $=
      ( leao df-le1 ) ABABACDE $.
      $( [27-Aug-97] $)
  $}

  ${
    df2le2.1 $e |- a =< b $.
    $( Alternate definition of 'less than or equal to'. $)
    df2le2 $p |- ( a ^ b ) = a $=
      ( df-le2 leoa ) ABBABCDE $.
      $( [27-Aug-97] $)
  $}

  ${
    letr.1 $e |- a =< b $.
    letr.2 $e |- b =< c $.
    $( Transitive law for l.e. $)
    letr   $p |- a =< c $=
      ( wa wo df-le2 ax-r5 ax-r1 ax-a3 3tr2 lan a5c ax-r2 df2le1 ) ACACFAABCGZG
      ZFACRAQABGZCGZCRTQSBCABDHIJBCEHABCKLMAQNOP $.
      $( [27-Aug-97] $)
  $}

  ${
    bltr.1 $e |- a = b $.
    bltr.2 $e |- b =< c $.
    $( Transitive inference. $)
    bltr $p |- a =< c $=
      ( wo ax-r5 df-le2 ax-r2 df-le1 ) ACACFBCFCABCDGBCEHIJ $.
      $( [28-Aug-97] $)
  $}

  ${
    lbtr.1 $e |- a =< b $.
    lbtr.2 $e |- b = c $.
    $( Transitive inference. $)
    lbtr $p |- a =< c $=
      ( wa ax-r1 lan df2le2 ax-r2 df2le1 ) ACACFABFACBABCEGHABDIJK $.
      $( [28-Aug-97] $)
  $}

  ${
    le3tr1.1 $e |- a =< b $.
    le3tr1.2 $e |- c = a $.
    le3tr1.3 $e |- d = b $.
    $( Transitive inference useful for introducing definitions. $)
    le3tr1 $p |- c =< d $=
      ( bltr ax-r1 lbtr ) CBDCABFEHDBGIJ $.
      $( [27-Aug-97] $)
  $}

  ${
    le3tr2.1 $e |- a =< b $.
    le3tr2.2 $e |- a = c $.
    le3tr2.3 $e |- b = d $.
    $( Transitive inference useful for eliminating definitions. $)
    le3tr2 $p |- c =< d $=
      ( ax-r1 le3tr1 ) ABCDEACFHBDGHI $.
      $( [27-Aug-97] $)
  $}

  ${
    bile.1 $e |- a = b $.
    $( Biconditional to l.e. $)
    bile   $p |- a =< b $=
      ( wo ax-r5 oridm ax-r2 df-le1 ) ABABDBBDBABBCEBFGH $.
      $( [27-Aug-97] $)
  $}

  $( An ortholattice inequality, corresponding to a theorem provable in
     Hilbert space.  Part of Definition 2.1 p. 2092, in M. Pavicic and N.
     Megill, "Quantum and Classical Implicational Algebras with Primitive
     Implication," _Int. J. of Theor. Phys._ 37, 2091-2098 (1998). $)
  qlhoml1a $p |- a =< a ' ' $=
    ( wn ax-a1 bile ) AABBACD $.
    $( [3-Feb-02] $)

  $( An ortholattice inequality, corresponding to a theorem provable in
     Hilbert space. $)
  qlhoml1b $p |- a ' ' =< a $=
    ( wn ax-a1 ax-r1 bile ) ABBZAAFACDE $.
    $( [3-Feb-02] $)

  ${
    lebi.1 $e |- a =< b $.
    lebi.2 $e |- b =< a $.
    $( L.e. to biconditional. $)
    lebi   $p |- a = b $=
      ( wo df-le2 ax-r1 ax-a2 ax-r2 ) AABEZBABAEZJKABADFGBAHIABCFI $.
      $( [27-Aug-97] $)
  $}

  $( Anything is l.e. 1. $)
  le1 $p |- a =< 1 $=
    ( wt or1 df-le1 ) ABACD $.
    $( [30-Aug-97] $)

  $( 0 is l.e. anything. $)
  le0 $p |- 0 =< a $=
    ( wf wo ax-a2 or0 ax-r2 df-le1 ) BABACABCABADAEFG $.
    $( [30-Aug-97] $)

  $( Identity law for less-than-or-equal. $)
  leid $p |- a =< a $=
    ( id bile ) AAABC $.
    $( [24-Dec-98] $)

  ${
    le.1 $e |- a =< b $.
    $( Add disjunct to right of l.e. $)
    ler $p |- a =< ( b v c ) $=
      ( wo ax-a3 ax-r1 df-le2 ax-r5 ax-r2 df-le1 ) ABCEZALEZABEZCEZLOMABCFGNBCA
      BDHIJK $.
      $( [27-Aug-97] $)

    $( Add disjunct to right of l.e. $)
    lerr $p |- a =< ( c v b ) $=
      ( wo ler ax-a2 lbtr ) ABCECBEABCDFBCGH $.
      $( [11-Nov-97] $)

    $( Add conjunct to left of l.e. $)
    lel $p |- ( a ^ c ) =< b $=
      ( wa an32 df2le2 ran ax-r2 df2le1 ) ACEZBKBEABEZCEKACBFLACABDGHIJ $.
      $( [27-Aug-97] $)

    $( Add disjunct to right of both sides $)
    leror $p |- ( a v c ) =< ( b v c ) $=
      ( wo orordir ax-r1 df-le2 ax-r5 ax-r2 df-le1 ) ACEZBCEZLMEZABEZCEZMPNABCF
      GOBCABDHIJK $.
      $( [27-Aug-97] $)

    $( Add conjunct to right of both sides $)
    leran $p |- ( a ^ c ) =< ( b ^ c ) $=
      ( wa anandir ax-r1 df2le2 ran ax-r2 df2le1 ) ACEZBCEZLMEZABEZCEZLPNABCFGO
      ACABDHIJK $.
      $( [27-Aug-97] $)

    $( Contrapositive for l.e. $)
    lecon $p |- b ' =< a ' $=
      ( wn wa wo ax-a2 oran df-le2 3tr2 con3 df2le1 ) BDZADZMNEZBBAFABFODBBAGBA
      HABCIJKL $.
      $( [27-Aug-97] $)
  $}

  ${
    lecon1.1 $e |- a ' =< b ' $.
    $( Contrapositive for l.e. $)
    lecon1 $p |- b =< a $=
      ( wn lecon ax-a1 le3tr1 ) BDZDADZDBAIHCEBFAFG $.
      $( [7-Nov-97] $)
  $}

  ${
    lecon2.1 $e |- a ' =< b $.
    $( Contrapositive for l.e. $)
    lecon2 $p |- b ' =< a $=
      ( wn ax-a1 lbtr lecon1 ) ABDZADBHDCBEFG $.
      $( [19-Dec-98] $)
  $}

  ${
    lecon3.1 $e |- a =< b ' $.
    $( Contrapositive for l.e. $)
    lecon3 $p |- b =< a ' $=
      ( wn lecon lecon2 lecon1 ) ADZBBDZHAICEFG $.
      $( [19-Dec-98] $)
  $}

  $( L.e. absorption. $)
  leo $p |- a =< ( a v b ) $=
    ( wo a5c df2le1 ) AABCABDE $.
    $( [27-Aug-97] $)

  $( L.e. absorption. $)
  leor $p |- a =< ( b v a ) $=
    ( wo leo ax-a2 lbtr ) AABCBACABDABEF $.
    $( [11-Nov-97] $)

  $( L.e. absorption. $)
  lea $p |- ( a ^ b ) =< a $=
    ( wa wo ax-a2 a5b ax-r2 df-le1 ) ABCZAIADAIDAIAEABFGH $.
    $( [27-Aug-97] $)

  $( L.e. absorption. $)
  lear $p |- ( a ^ b ) =< b $=
    ( wa ancom lea bltr ) ABCBACBABDBAEF $.
    $( [11-Nov-97] $)

  $( L.e. absorption. $)
  leao1 $p |- ( a ^ b ) =< ( a v c ) $=
    ( wa wo lea leo letr ) ABDAACEABFACGH $.
    $( [8-Jul-00] $)

  $( L.e. absorption. $)
  leao2 $p |- ( b ^ a ) =< ( a v c ) $=
    ( wa wo lear leo letr ) BADAACEBAFACGH $.
    $( [8-Jul-00] $)

  $( L.e. absorption. $)
  leao3 $p |- ( a ^ b ) =< ( c v a ) $=
    ( wa wo lea leor letr ) ABDACAEABFACGH $.
    $( [8-Jul-00] $)

  $( L.e. absorption. $)
  leao4 $p |- ( b ^ a ) =< ( c v a ) $=
    ( wa wo lear leor letr ) BADACAEBAFACGH $.
    $( [8-Jul-00] $)

  ${
    lel.1 $e |- a =< b $.
    $( Add disjunct to left of both sides $)
    lelor $p |- ( c v a ) =< ( c v b ) $=
      ( wo leror ax-a2 le3tr1 ) ACEBCECAECBEABCDFCAGCBGH $.
      $( [25-Oct-97] $)

    $( Add conjunct to left of both sides $)
    lelan $p |- ( c ^ a ) =< ( c ^ b ) $=
      ( wa leran ancom le3tr1 ) ACEBCECAECBEABCDFCAGCBGH $.
      $( [25-Oct-97] $)
  $}

  ${
    le2.1 $e |- a =< b $.
    le2.2 $e |- c =< d $.
    $( Disjunction of 2 l.e.'s $)
    le2or $p |- ( a v c ) =< ( b v d ) $=
      ( wo leror lelor letr ) ACGBCGBDGABCEHCDBFIJ $.
      $( [25-Oct-97] $)

    $( Conjunction of 2 l.e.'s $)
    le2an $p |- ( a ^ c ) =< ( b ^ d ) $=
      ( wa leran lelan letr ) ACGBCGBDGABCEHCDBFIJ $.
      $( [25-Oct-97] $)
  $}

  ${
    lel2.1 $e |- a =< b $.
    lel2.2 $e |- c =< b $.
    $( Disjunction of 2 l.e.'s $)
    lel2or $p |- ( a v c ) =< b $=
      ( wo le2or oridm lbtr ) ACFBBFBABCBDEGBHI $.
      $( [11-Nov-97] $)

    $( Conjunction of 2 l.e.'s $)
    lel2an $p |- ( a ^ c ) =< b $=
      ( wa le2an anidm lbtr ) ACFBBFBABCBDEGBHI $.
      $( [11-Nov-97] $)
  $}

  ${
    ler2.1 $e |- a =< b $.
    ler2.2 $e |- a =< c $.
    $( Disjunction of 2 l.e.'s $)
    ler2or $p |- a =< ( b v c ) $=
      ( wo oridm ax-r1 le2or bltr ) AAAFZBCFKAAGHABACDEIJ $.
      $( [11-Nov-97] $)

    $( Conjunction of 2 l.e.'s $)
    ler2an $p |- a =< ( b ^ c ) $=
      ( wa anidm ax-r1 le2an bltr ) AAAFZBCFKAAGHABACDEIJ $.
      $( [11-Nov-97] $)
  $}

  $( Half of distributive law. $)
  ledi $p |- ( ( a ^ b ) v ( a ^ c ) ) =< ( a ^ ( b v c ) ) $=
    ( wa wo anidm ax-r1 lea le2or oridm lbtr ancom bltr le2an ) ABDZACDZEZQQDZA
    BCEZDRQQFGQAQSQAAEAOAPAABHACHIAJKOBPCOBADBABLBAHMPCADCACLCAHMINM $.
    $( [28-Aug-97] $)

  $( Half of distributive law. $)
  ledir $p |- ( ( b ^ a ) v ( c ^ a ) ) =< ( ( b v c ) ^ a ) $=
    ( wa wo ledi ancom 2or le3tr1 ) ABDZACDZEABCEZDBADZCADZELADABCFMJNKBAGCAGHL
    AGI $.
    $( [30-Nov-98] $)

  $( Half of distributive law. $)
  ledio $p |- ( a v ( b ^ c ) ) =< ( ( a v b ) ^ ( a v c ) ) $=
    ( wa wo anidm ax-r1 leo le2an bltr ax-a2 lbtr le2or oridm ) ABCDZEABEZACEZD
    ZRERARORAAADZRSAAFGAPAQABHACHIJBPCQBBAEPBAHBAKLCCAEQCAHCAKLIMRNL $.
    $( [28-Aug-97] $)

  $( Half of distributive law. $)
  ledior $p |- ( ( b ^ c ) v a ) =< ( ( b v a ) ^ ( c v a ) ) $=
    ( wa wo ledio ax-a2 2an le3tr1 ) ABCDZEABEZACEZDJAEBAEZCAEZDABCFJAGMKNLBAGC
    AGHI $.
    $( [30-Nov-98] $)

  $( Commutation with 0.  Kalmbach 83 p. 20. $)
  comm0 $p |- a C 0 $=
    ( wf wo wa wn ax-a2 or0 ax-r2 ax-r1 an0 wt df-f con2 lan an1 2or df-c1 ) AB
    ABACZABDZABEZDZCZRARABCABAFAGHIUBRSBUAAAJUAAKDATKABKLMNAOHPIHQ $.
    $( [27-Aug-97] $)

  $( Commutation with 1.  Kalmbach 83 p. 20. $)
  comm1 $p |- 1 C a $=
    ( wt wn wo wa df-t ancom an1 ax-r2 2or ax-r1 df-c1 ) BABAACZDZBAEZBMEZDZAFQ
    NOAPMOABEABAGAHIPMBEMBMGMHIJKIL $.
    $( [27-Aug-97] $)

  ${
    lecom.1 $e |- a =< b $.
    $( Comparable elements commute.  Beran 84 2.3(iii) p. 40. $)
    lecom $p |- a C b $=
      ( wn wa wo a5b ax-r1 df2le2 ax-r5 ax-r2 df-c1 ) ABAAABDZEZFZABEZNFOAAMGHA
      PNPAABCIHJKL $.
      $( [30-Aug-97] $)
  $}

  ${
    bctr.1 $e |- a = b $.
    bctr.2 $e |- b C c $.
    $( Transitive inference. $)
    bctr $p |- a C c $=
      ( wa wn wo df-c2 ran 2or 3tr1 df-c1 ) ACBBCFZBCGZFZHAACFZAOFZHBCEIDQNRPAB
      CDJABODJKLM $.
      $( [30-Aug-97] $)
  $}

  ${
    cbtr.1 $e |- a C b $.
    cbtr.2 $e |- b = c $.
    $( Transitive inference. $)
    cbtr $p |- a C c $=
      ( wa wn wo df-c2 lan ax-r4 2or ax-r2 df-c1 ) ACAABFZABGZFZHACFZACGZFZHABD
      IORQTBCAEJPSABCEKJLMN $.
      $( [30-Aug-97] $)
  $}

  ${
    comcom2.1 $e |- a C b $.
    $( Commutation equivalence.  Kalmbach 83 p. 23. Does not use OML. $)
    comcom2 $p |- a C b ' $=
      ( wn wa wo df-c2 ax-a1 lan ax-r5 ax-r2 ax-a2 df-c1 ) ABDZAANDZEZANEZFZQPF
      AABEZQFRABCGSPQBOABHIJKPQLKM $.
      $( [27-Aug-97] $)
  $}

  $( Commutation law.  Does not use OML. $)
  comorr $p |- a C ( a v b ) $=
    ( wo leo lecom ) AABCABDE $.
    $( [30-Aug-97] $)

  $( Commutation law.  Does not use OML. $)
  coman1 $p |- ( a ^ b ) C a $=
    ( wa lea lecom ) ABCAABDE $.
    $( [30-Aug-97] $)

  $( Commutation law.  Does not use OML. $)
  coman2 $p |- ( a ^ b ) C b $=
    ( wa ancom coman1 bctr ) ABCBACBABDBAEF $.
    $( [9-Nov-97] $)

  $( Identity law for commutation.  Does not use OML. $)
  comid $p |- a C a $=
    ( wo comorr oridm cbtr ) AAABAAACADE $.
    $( [9-Nov-97] $)

  ${
    distlem.1 $e |- ( a ^ ( b v c ) ) =< b $.
    $( Distributive law inference (uses OL only). $)
    distlem $p |- ( a ^ ( b v c ) ) = ( ( a ^ b ) v ( a ^ c ) ) $=
      ( wo wa lea ler2an leo letr ledi lebi ) ABCEZFZABFZACFZEZNOQNABAMGDHOPIJA
      BCKL $.
      $( [17-Nov-98] $)
  $}

  ${
    str.1 $e |- a =< ( b v c ) $.
    str.2 $e |- ( a ^ ( b v c ) ) =< b $.
    $( Strengthening rule. $)
    str   $p |- a =< b $=
      ( wo wa id bile ler2an letr ) AABCFZGBAALAAAHIDJEK $.
      $( [18-Nov-98] $)
  $}

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Commutator (ortholattice theorems)
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

 $( Commutative law for commutator. $)
 cmtrcom $p |- C ( a , b ) = C ( b , a ) $=
   ( wa wn wo wcmtr ancom 2or or4 ax-r2 df-cmtr 3tr1 ) ABCZABDZCZEZADZBCZQNCZEZ
   EZBACZBQCZENACZNQCZEEZABFBAFUAUBUDEZUCUEEZEUFPUGTUHMUBOUDABGANGHRUCSUEQBGQNG
   HHUBUDUCUEIJABKBAKL $.
   $( [24-Jan-99] $)

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Weak "orthomodular law" in ortholattices.
        All theorems here do not require R3 and
        are true in all ortholattices.
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( Weak A1. $)
  wa1 $p |- ( a == a ' '  ) = 1 $=
    ( wn ax-a1 bi1 ) AABBACD $.
    $( [27-Sep-97] $)

  $( Weak A2. $)
  wa2 $p |- ( ( a v b ) == ( b v a ) ) = 1 $=
    ( wo ax-a2 bi1 ) ABCBACABDE $.
    $( [27-Sep-97] $)

  $( Weak A3. $)
  wa3 $p |- ( ( ( a v b ) v c ) == ( a v ( b v c ) ) ) = 1 $=
    ( wo ax-a3 bi1 ) ABDCDABCDDABCEF $.
    $( [27-Sep-97] $)

  $( Weak A4. $)
  wa4 $p |- ( ( a v ( b v b ' ) ) == ( b v b ' ) ) = 1 $=
    ( wn wo ax-a4 bi1 ) ABBCDZDGABEF $.
    $( [27-Sep-97] $)

  $( Weak A5. $)
  wa5 $p |- ( ( a v ( a ' v b ' ) ' ) == a ) = 1 $=
    ( wn wo ax-a5 bi1 ) AACBCZDCDAAGEF $.
    $( [27-Sep-97] $)

  $( Weak A6. $)
  wa6 $p |- ( ( a == b ) == ( ( a ' v  b ' ) ' v ( a v b ) ' ) )
             = 1 $=
    ( tb wn wo df-b bi1 ) ABCADBDEDABEDEABFG $.
    $( [12-Jul-98] $)

  ${
    wr1.1 $e |- ( a == b ) = 1 $.
    $( Weak R1. $)
    wr1   $p |- ( b == a ) = 1 $=
      ( tb wt bicom ax-r2 ) BADABDEBAFCG $.
      $( [2-Sep-97] $)
  $}

  ${
    wr3.1 $e |- ( 1 == a ) = 1 $.
    $( Weak R3. $)
    wr3   $p |- a = 1 $=
      ( wt tb 1b ax-r1 ax-r2 ) ACADZCHAAEFBG $.
      $( [2-Sep-97] $)
  $}

  ${
    wr4.1 $e |- ( a == b ) = 1 $.
    $( Weak R4. $)
    wr4   $p |- ( a ' == b ' ) = 1 $=
      ( wn tb wt conb ax-r1 ax-r2 ) ADBDEZABEZFKJABGHCI $.
      $( [2-Sep-97] $)
  $}

  $( Absorption law. $)
  wa5b $p |- ( ( a v ( a ^ b ) ) == a ) = 1 $=
    ( wa wo a5b bi1 ) AABCDAABEF $.
    $( [27-Sep-97] $)

  $( Absorption law. $)
  wa5c $p |- ( ( a ^ ( a v b ) ) == a ) = 1 $=
    ( wo wa a5c bi1 ) AABCDAABEF $.
    $( [27-Sep-97] $)

  $( Contraposition law. $)
  wcon $p |- ( ( a == b ) == ( a ' == b ' ) ) = 1 $=
    ( tb wn conb bi1 ) ABCADBDCABEF $.
    $( [27-Sep-97] $)

  $( Commutative law. $)
  wancom $p |- ( ( a ^ b ) == ( b ^ a ) ) = 1 $=
    ( wa ancom bi1 ) ABCBACABDE $.
    $( [27-Sep-97] $)

  $( Associative law. $)
  wanass $p |- ( ( ( a ^ b ) ^ c ) == ( a ^ ( b ^ c ) ) ) = 1 $=
    ( wa anass bi1 ) ABDCDABCDDABCEF $.
    $( [27-Sep-97] $)

  ${
    wwbmp.1 $e |- a = 1 $.
    wwbmp.2 $e |- ( a == b ) = 1 $.
    $( Weak weak equivalential detachment (WBMP). $)
    wwbmp $p |- b = 1 $=
      ( wt tb rbi ax-r1 ax-r2 wr3 ) BEBFZABFZELKAEBCGHDIJ $.
      $( [2-Sep-97] $)
  $}

  ${
    wwbmpr.1 $e |- b = 1 $.
    wwbmpr.2 $e |- ( a == b ) = 1 $.
    $( Weak weak equivalential detachment (WBMP). $)
    wwbmpr $p |- a = 1 $=
      ( wr1 wwbmp ) BACABDEF $.
      $( [24-Sep-97] $)
  $}

  ${
    wcon1.1 $e |- ( a ' == b ' ) = 1 $.
    $( Weak contraposition. $)
    wcon1   $p |- ( a == b ) = 1 $=
      ( tb wn wt conb ax-r2 ) ABDAEBEDFABGCH $.
      $( [24-Sep-97] $)
  $}

  ${
    wcon2.1 $e |- ( a == b ' ) = 1 $.
    $( Weak contraposition. $)
    wcon2   $p |- ( a ' == b ) = 1 $=
      ( wn tb wt conb ax-a1 rbi ax-r1 ax-r2 ) ADZBEZABDZEZFMLDZNEZOLBGOQAPNAHIJ
      KCK $.
      $( [24-Sep-97] $)
  $}

  ${
    wcon3.1 $e |- ( a ' == b ) = 1 $.
    $( Weak contraposition. $)
    wcon3   $p |- ( a == b ' ) = 1 $=
      ( wn tb wt ax-a1 ax-r1 lbi ax-r2 wcon1 ) ABDZADZLDZEMBEFNBMBNBGHICJK $.
      $( [24-Sep-97] $)
  $}

  ${
    wlem3.1.1 $e |- ( a v b ) = b $.
    wlem3.1.2 $e |- ( b ' v a ) = 1 $.
    $( Weak analogue to lemma used in proof of Th. 3.1 of Pavicic 1993. $)
    wlem3.1 $p |- ( a == b ) = 1 $=
      ( tb wn wo wt wa dfb leoa oran ax-r1 ax-r2 con3 2or ax-a2 ) ABEZBFZAGZHRA
      BIZAFSIZGZTABJUCASGTUAAUBSABBCKUBBUBFZABGZBUEUDABLMCNOPASQNNDN $.
      $( [2-Sep-97] $)
  $}

  $( Theorem structurally similar to orthomodular law but does not require
     R3. $)
  woml $p |- ( ( a v ( a ' ^ ( a v b ) ) ) == ( a v b ) ) = 1 $=
    ( wn wo wa omlem1 omlem2 wlem3.1 ) AACABDZEDIABFABGH $.
    $( [2-Sep-97] $)

  ${
    wwoml2.1 $e |- a =< b $.
    $( Weak orthomodular law. $)
    wwoml2 $p |- ( ( a v ( a ' ^ b ) ) == b ) = 1 $=
      ( wn wa wo tb wt df-le2 ax-r1 lan lor rbi lbi woml 3tr2 ) AADZBEZFZABFZGA
      QTEZFZTGSBGHSUBTRUAABTQTBABCIZJKLMTBSUCNABOP $.
      $( [2-Sep-97] $)
  $}

  ${
    wwoml3.1 $e |- a =< b $.
    wwoml3.2 $e |- ( b ^ a ' ) = 0 $.
    $( Weak orthomodular law. $)
    wwoml3 $p |- ( a == b ) = 1 $=
      ( wf wo tb wn wa wt ax-r1 ancom ax-r2 lor rbi or0 wwoml2 3tr2 ) AEFZBGAAH
      ZBIZFZBGABGJSUBBEUAAEBTIZUAUCEDKBTLMNOSABAPOABCQR $.
      $( [2-Sep-97] $)
  $}

  ${
    wwcomd.1 $e |- a ' C b $.
    $( Commutation dual (weak).  Kalmbach 83 p. 23. $)
    wwcomd $p |- a = ( ( a v b ) ^ ( a v b ' ) ) $=
      ( wo wn wa df-c2 oran ax-a2 anor2 ax-r1 con3 2an ax-r4 3tr1 ax-r2 con1 )
      AABDZABEZDZFZAEZUBBFZUBSFZDZUAEZUBBCGUDUCDUDEZUCEZFZEUEUFUDUCHUCUDIUAUIRU
      GTUHABHTUCUCTEABJKLMNOPQ $.
      $( [2-Sep-97] $)

  $}

  ${
    wwcom3ii.1 $e |- b ' C a $.
    $( Lemma 3(ii) (weak) of Kalmbach 83 p. 23. $)
    wwcom3ii $p |- ( a ^ ( a ' v b ) ) = ( a ^ b ) $=
      ( wa wn wo wwcomd lan anass ax-r1 ax-a2 a5c ax-r2 2an ) ABDZAAEZBFZDZOABA
      FZBPFZDZDZRBUAABACGHUBASDZTDZRUDUBASTIJUCATQUCAABFZDASUEABAKHABLMBPKNMMJ
      $.
      $( [2-Sep-97] $)
  $}

  ${
    wwfh.1 $e |- b C a $.
    wwfh.2 $e |- c C a $.
    $( Foulis-Holland Theorem (weak). $)
    wwfh1 $p |- ( ( a ^ ( b v c ) ) == ( ( a ^ b ) v ( a ^ c ) ) )
               = 1 $=
      ( wo wa tb wt bicom ledi wn wf ancom df-a 2or ax-r1 con3 ax-r2 con2 2an
      anass ax-a1 bctr wwcom3ii anandi 3tr1 lan an12 oran dff an0 wwoml3 ) ABCF
      ZGZABGZACGZFZHURUOHIUOURJURUOABCKUOURLZGZAUNBLZCLZGZGZGZMUTUNAGZALZVAFZVG
      VBFZGZGZVEUOVFUSVJAUNNURVJURVHLZVILZFZVJLUPVLUQVMABOACOPVNVJVJVNLVHVIOQRS
      TUAVKUNAVCGZGZVEVKUNAVJGZGVPUNAVJUBVQVOUNAVHGZAVIGZGAVAGZAVBGZGVQVOVRVTVS
      WAAVAVALZBABWBBUCQDUDUEAVBVBLZCACWCCUCQEUDUEUAAVHVIUFAVAVBUFUGUHSUNAVCUIS
      SVEAMGMVDMAVDUNUNLZGZMVCWDUNVCUNUNVCLBCUJQRUHMWEUNUKQSUHAULSSUMS $.
      $( [3-Sep-97] $)
  $}

  ${
    wwfh2.1 $e |- a C b $.
    wwfh2.2 $e |- c ' C a $.
    $( Foulis-Holland Theorem (weak). $)
    wwfh2 $p |- ( ( b ^ ( a v c ) ) == ( ( b ^ a ) v ( b ^ c ) ) )
               = 1 $=
      ( wo wa tb wt bicom ledi wn wf oran df-a con2 ran ax-r4 ax-r2 lan an4
      ax-a1 ax-r1 bctr wwcom3ii ancom ax-r5 comcom2 anass an12 dff 3tr1 an0
      wwoml3 ) BACFZGZBAGZBCGZFZHUSUPHIUPUSJUSUPBACKUPUSLZGZALZCBURLZGZGZGZMVAV
      BCGZVDGZVFVAVBUOGZVDGZVHVAVBBGZUOVCGZGZVJVAUPBLVBFZVCGZGZVMUTVOUPUSVOUSUQ
      LZVCGZLVOLUQURNVRVOVQVNVCUQVNBAOPQRSPTVPBVNGZVLGVMBUOVNVCUAVSVKVLVSBVBGVK
      BVBVBLZABAVTAUBZUCDUDUEBVBUFSQSSVBBUOVCUASVIVGVDVIVBVTCFZGVGUOWBVBAVTCWAU
      GTVBCCLAEUHUESQSVBCVDUISVFVBMGMVEMVBBCVCGGZURVCGZVEMWDWCBCVCUIUCCBVCUJURU
      KULTVBUMSSUNS $.
      $( [3-Sep-97] $)

  $}

  ${
    wwfh3.1 $e |- b ' C a $.
    wwfh3.2 $e |- c ' C a $.
    $( Foulis-Holland Theorem (weak). $)
    wwfh3 $p |- ( ( a v ( b ^ c ) ) == ( ( a v b ) ^ ( a v c ) ) )
               = 1 $=
      ( wa wo tb wn wt conb oran df-a con2 lan ax-r4 ax-r2 2or 2bi comcom2
      wwfh1 ) ABCFZGZABGZACGZFZHZAIZBIZCIZGZFZUHUIFZUHUJFZGZHZJUGUCIZUFIZHUPUCU
      FKUQULURUOUCULUCUHUBIZFZIULIAUBLUTULUSUKUHUBUKBCMNOPQNUFUOUFUDIZUEIZGZIUO
      IUDUEMVCUOVAUMVBUNUDUMABLNUEUNACLNRPQNSQUHUIUJUIADTUJAETUAQ $.
      $( [3-Sep-97] $)
  $}

  ${
    wwfh4.1 $e |- a ' C b $.
    wwfh4.2 $e |- c C a $.
    $( Foulis-Holland Theorem (weak). $)
    wwfh4 $p |- ( ( b v ( a ^ c ) ) == ( ( b v a ) ^ ( b v c ) ) )
               = 1 $=
      ( wa wo tb wn wt conb oran df-a con2 lan ax-r4 ax-r2 2or 2bi comcom2
      ax-a1 ax-r1 bctr wwfh2 ) BACFZGZBAGZBCGZFZHZBIZAIZCIZGZFZUKULFZUKUMFZGZHZ
      JUJUFIZUIIZHUSUFUIKUTUOVAURUFUOUFUKUEIZFZIUOIBUELVCUOVBUNUKUEUNACMNOPQNUI
      URUIUGIZUHIZGZIURIUGUHMVFURVDUPVEUQUGUPBALNUHUQBCLNRPQNSQULUKUMULBDTUMIZA
      VGCACVGCUAUBEUCTUDQ $.
      $( [3-Sep-97] $)
  $}

  $( Weak OM-like absorption law for ortholattices. $)
  womao $p |- ( a ' ^ ( a v ( a ' ^ ( a v b ) ) ) ) =
                                ( a ' ^ ( a v b ) ) $=
    ( wn wo wa lea lear leo lel2or letr ler2an leor lebi ) ACZANABDZEZDZEZPRNON
    QFRQONQGAOPABHNOGIJKPNQNOFPALKM $.
    $( [8-Nov-98] $)

  $( Weak OM-like absorption law for ortholattices. $)
  womaon $p |- ( a ^ ( a ' v ( a ^ ( a ' v b ) ) ) ) =
                                 ( a ^ ( a ' v b ) ) $=
    ( wn wo wa lea lear leo lel2or letr ler2an leor lebi ) AACZANBDZEZDZEZPRAOA
    QFRQOAQGNOPNBHAOGIJKPAQAOFPNLKM $.
    $( [8-Nov-98] $)

  $( Weak OM-like absorption law for ortholattices. $)
  womaa $p |- ( a ' v ( a ^ ( a ' v ( a ^ b ) ) ) ) =
                                ( a ' v ( a ^ b ) ) $=
    ( wn wa wo leo lear lel2or lea leor ler2an letr lebi ) ACZANABDZEZDZEZPNPQN
    OFAPGHNRONQFOQROAPABIONJKQNJLHM $.
    $( [8-Nov-98] $)

  $( Weak OM-like absorption law for ortholattices. $)
  womaan $p |- ( a v ( a ' ^ ( a v ( a ' ^ b ) ) ) ) =
                                 ( a v ( a ' ^ b ) ) $=
    ( wn wa wo leo lear lel2or lea leor ler2an letr lebi ) AACZANBDZEZDZEZPAPQA
    OFNPGHAROAQFOQRONPNBIOAJKQAJLHM $.
    $( [8-Nov-98] $)

  $( Absorption law for ortholattices. $)
  anorabs2 $p |- ( a ^ ( b v ( a ^ ( b v c ) ) ) ) =
                                 ( a ^ ( b v c ) ) $=
    ( wo wa lea lear leo lel2or letr ler2an leor lebi ) ABABCDZEZDZEZOQANAPFQPN
    APGBNOBCHANGIJKOAPANFOBLKM $.
    $( [13-Nov-98] $)

  $( Absorption law for ortholattices. $)
  anorabs $p |- ( a ' ^ ( b v ( a ' ^ ( a v b ) ) ) ) =
                                  ( a ' ^ ( a v b ) ) $=
    ( wn wo wa anorabs2 ax-a2 lan lor 3tr1 ) ACZBKBADZEZDZEMKBKABDZEZDZEPKBAFQN
    KPMBOLKABGHZIHRJ $.
    $( [8-Nov-98] $)

  $( Axiom KA2a in Pavicic and Megill, 1998 $)
  ska2a $p |- ( ( ( a v c ) == ( b v c ) ) ==
              ( ( c v a ) == ( c v b ) ) ) = 1 $=
    ( wo tb ax-a2 2bi bi1 ) ACDZBCDZECADZCBDZEIKJLACFBCFGH $.
    $( [9-Nov-98] $)

  $( Axiom KA2b in Pavicic and Megill, 1998 $)
  ska2b $p |- ( ( ( a v c ) == ( b v c ) ) ==
              ( ( a ' ^ c ' ) ' == ( b ' ^ c ' ) ' ) ) = 1 $=
    ( wo tb wn wa oran 2bi bi1 ) ACDZBCDZEAFCFZGFZBFMGFZEKNLOACHBCHIJ $.
    $( [9-Nov-98] $)

  $( Lemma for KA4 soundness (OR version) - uses OL only. $)
  ka4lemo $p |- ( ( a v b ) v ( ( a v c ) == ( b v c ) ) ) = 1 $=
    ( wo tb wt le1 wn df-t wa leo ax-a2 lbtr lelor leror ax-a3 ledio 2an
    le3tr1 dfb oran con2 anor1 anandir ax-r1 ax-r5 ax-r4 3tr1 ax-r2 lor bltr
    letr lebi ) ABDZACDZBCDZEZDZFURGFUNCDZUSHZDZURUSIVAUNABJZCDZDZUTDZURUSVDUTC
    VCUNCCVBDZVCCVBKCVBLMNOVEUNVCUTDZDURUNVCUTPVGUQUNVGUOUPJZUTDZUQVCVHUTVFCADZ
    CBDZJVCVHCABQVBCLUOVJUPVKACLBCLRSOUQVIUQVHUOHZUPHZJZDVIUOUPTVNUTVHVNAHZCHZJ
    ZBHZVPJZJZUTVLVQVMVSUOVQACUAUBUPVSBCUAUBRVOVRJZVPJZWAHZCDZHVTUTWACUCWBVTVOV
    RVPUDUEUSWDUNWCCABUAUFUGUHUIUJUIUEMNUKULUKUM $.
    $( [25-Oct-97] $)

  $( Lemma for KA4 soundness (AND version) - uses OL only. $)
  ka4lem $p |- ( ( a ^ b ) ' v ( ( a ^ c ) == ( b ^ c ) ) ) = 1 $=
    ( wa wn tb wo wt df-a con2 2bi conb ax-r1 ax-r2 2or ka4lemo ) ABDZEZACDZBCD
    ZFZGAEZBEZGZUBCEZGZUCUEGZFZGHRUDUAUHQUDABIJUAUFEZUGEZFZUHSUITUJACIBCIKUHUKU
    FUGLMNOUBUCUEPN $.
    $( [25-Oct-97] $)


$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Kalmbach axioms (soundness proofs) that are true in all
        ortholattices
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  ${
    sklem.1 $e |- a =< b $.
    $( Soundness lemma. $)
    sklem   $p |- ( a ' v b ) = 1 $=
      ( wn wo wt or12 df-t ax-r5 ax-r1 ax-a3 ax-a2 3tr2 ax-r2 df-le2 lor or1 )
      ADZABEZEZBFEZRBEZFTAUBEZUARABGAREZBEZFBEZUCUAUFUEFUDBAHIJARBKFBLMNSBRABCO
      PBQM $.
      $( [30-Aug-97] $)
  $}

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA1. $)
  ska1 $p |- ( a == a ) = 1 $=
    ( biid ) AB $.
    $( [30-Aug-97] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA3. $)
  ska3 $p |- ( ( a == b ) ' v ( a ' == b ' ) ) = 1 $=
    ( wn tb wo wt conb ax-r4 lor ax-a2 df-t 3tr1 ) ACBCDZABDZCZEMMCZEOMEFOPMNMA
    BGHIOMJMKL $.
    $( [30-Aug-97] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA5. $)
  ska5 $p |- ( ( a ^ b ) == ( b ^ a ) ) = 1 $=
    ( wa ancom bi1 ) ABCBACABDE $.
    $( [30-Aug-97] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA6. $)
  ska6 $p |- ( ( a ^ ( b ^ c ) ) == ( ( a ^ b ) ^ c ) ) = 1 $=
    ( wa anass ax-r1 bi1 ) ABCDDZABDCDZIHABCEFG $.
    $( [30-Aug-97] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA7. $)
  ska7 $p |- ( ( a ^ ( a v b ) ) == a ) = 1 $=
    ( wo wa a5c bi1 ) AABCDAABEF $.
    $( [30-Aug-97] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA8. $)
  ska8 $p |- ( ( a ' ^ a ) == ( ( a ' ^ a ) ^ b ) ) = 1 $=
    ( wn wa wf an0 ax-r1 ancom ax-r2 dff ran 3tr2 bi1 ) ACZADZOBDZEEBDZOPEBEDZQ
    REBFGBEHIEANDOAJANHIZEOBSKLM $.
    $( [30-Aug-97] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA9. $)
  ska9 $p |- ( a == a ' ' ) = 1 $=
    ( wn ax-a1 bi1 ) AABBACD $.
    $( [30-Aug-97] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA10. $)
  ska10 $p |- ( ( a v b ) ' == ( a ' ^ b ' ) ) = 1 $=
    ( wo wn wa oran con2 bi1 ) ABCZDADBDEZIJABFGH $.
    $( [30-Aug-97] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA11. $)
  ska11 $p |- ( ( a v ( a ' ^ ( a v b ) ) ) == ( a v b ) ) = 1 $=
    ( woml ) ABC $.
    $( [2-Sep-97] $)
      $( [30-Aug-97] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA12. $)
  ska12 $p |- ( ( a == b ) == ( b == a ) ) = 1 $=
    ( tb bicom bi1 ) ABCBACABDE $.
    $( [30-Aug-97] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA13. $)
  ska13 $p |- ( ( a == b ) ' v ( a ' v b ) ) = 1 $=
    ( tb wn wo wa ledio lea letr ancom bltr leror dfb ax-a2 le3tr1 sklem ) ABCZ
    ADZBEZABFZRBDZFEZBREZQSUBTREZUCUBUDTUAEZFUDTRUAGUDUEHITBRTBAFBABJBAHKLIABMR
    BNOP $.
    $( [30-Aug-97] $)

  ${
    skr0.1 $e |- a = 1 $.
    skr0.2 $e |- ( a ' v b ) = 1 $.
    $( Soundness theorem for Kalmbach's quantum propositional logic axiom KR0. $)
    skr0 $p |- b = 1 $=
      ( wn wo wt wf ax-a2 or0 ax-r1 ax-r4 df-f ax-r2 ax-r5 3tr1 ) BAEZBFZGBHFZH
      BFBRBHISBBJKQHBQGEZHAGCLHTMKNOPDN $.
      $( [30-Aug-97] $)
  $}

  $( Lemma for 2-variable WOML proof. $)
  wlem1 $p |- ( ( a == b ) ' v ( ( a ->1 b ) ^ ( b ->1 a ) ) ) = 1 $=
    ( tb wn wi1 wa wo wt le1 df-t ax-a2 ax-r2 dfb ledio df-i1 ancom ax-r5 2an
    ax-r1 lbtr bltr lelor lebi ) ABCZDZABEZBAEZFZGZHUIIHUEUDGZUIHUDUEGUJUDJUDUE
    KLUDUHUEUDABFZADZBDZFGZUHABMUNUKULGZUKUMGZFZUHUKULUMNUHUQUFUOUGUPUFULUKGUOA
    BOULUKKLUGUMBAFZGZUPBAOUSURUMGUPUMURKURUKUMBAPQLLRSTUAUBUAUC $.
    $( [11-Nov-98] $)

  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA15. $)
  ska15 $p |- ( ( a ->3 b ) ' v ( a ' v b ) ) = 1 $=
    ( wi3 wn wo wa df-i3 ax-a2 lea lear le2or bltr oridm lbtr sklem ) ABCZADZBE
    ZPQBFZQBDZFZEZARFZEZRABGUDRRERUBRUCRUBUASERSUAHUAQSBQTIQBJKLARJKRMNLO $.
    $( [2-Nov-97] $)

  ${
    skmp3.1 $e |- a = 1 $.
    skmp3.2 $e |- ( a ->3 b ) = 1 $.
    $( Soundness proof for KMP3. $)
    skmp3 $p |- b = 1 $=
      ( wi3 wn wo ska15 skr0 ) ABCABEAFBGDABHII $.
      $( [2-Nov-97] $)
  $}

  ${
    lei3.1 $e |- a =< b $.
    $( L.e. to Kalmbach implication. $)
    lei3 $p |- ( a ->3 b ) = 1 $=
      ( wn wa wo wi3 wt ax-a3 ax-a2 ancom lecon df2le2 ax-r2 sklem lan an1 2or
      anor2 con2 3tr1 lor df-i3 df-t ) ADZBEZUEBDZEZFAUEBFZEZFZUFUFDZFZABGHUKUF
      UHUJFZFUMUFUHUJIUNULUFUGAFAUGFZUNULUGAJUHUGUJAUHUGUEEUGUEUGKUGUEABCLMNUJA
      HEAUIHAABCOPAQNRUFUOABSTUAUBNABUCUFUDUA $.
      $( [3-Nov-97] $)
  $}

  $( E2 - OL theorem proved by EQP $)
  mccune2 $p |- ( a v ( ( a ' ^ ( ( a v b ' ) ^ ( a v b ) ) ) v (
                a ' ^ ( ( a ' ^ b ) v ( a ' ^ b ' ) ) ) ) ) = 1 $=
    ( wn wo wa wt ax-a3 ax-r1 anor2 lear lea lel2or id bile ler2an lebi anor3
    2or oran3 ax-r2 ax-a2 lor df-t 3tr1 ) AABCZDZABDZEZCZAUIDZCZDZDZUJUKDZAACZU
    HEZUOUOBEZUOUEEZDZEZDZDFUNUMAUIUKGHVAULAVAUKUIDULUPUKUTUIAUHIUTUSUIUTUSUOUS
    JUSUOUSUQUOURUOBKUOUEKLUSUSUSMNOPUSUFCZUGCZDUIUQVBURVCABIABQRUFUGSTTRUKUIUA
    TUBUJUCUD $.
    $( [14-Nov-98] $)

  $( E3 - OL theorem proved by EQP $)
  mccune3 $p |- ( ( ( ( a ' ^ b ) v ( a ' ^ b ' ) ) v ( a ^ ( a '
                v b ) ) ) ' v ( a ' v b ) ) = 1 $=
    ( wn wa wo wi3 wt df-i3 ax-r1 ax-r4 ax-r5 ska15 ax-r2 ) ACZBDNBCDEANBEZDEZC
    ZOEABFZCZOEGQSOPRRPABHIJKABLM $.
    $( [14-Nov-98] $)

  $( Equivalence for Kalmbach implication. $)
  i3n1 $p |- ( a ' ->3 b ' ) = ( ( ( a ^ b ' ) v ( a ^ b ) ) v
                ( a ' ^ ( a v b ' ) ) ) $=
    ( wn wi3 wa wo df-i3 ax-a1 ran 2an 2or ax-r5 lan ax-r1 ax-r2 ) ACZBCZDPCZQE
    ZRQCZEZFZPRQFZEZFZAQEZABEZFZPAQFZEZFZPQGUKUEUHUBUJUDUFSUGUAARQAHZIARBTULBHJ
    KUIUCPARQULLMKNO $.
    $( [9-Nov-97] $)

  $( Equivalence for Kalmbach implication. $)
  ni31 $p |- ( a ->3 b ) ' = ( ( ( a v b ' ) ^ ( a v b ) ) ^
                ( a ' v ( a ^ b ' ) ) ) $=
    ( wi3 wn wo wa df-i3 oran anor2 con2 ax-r1 2an ax-r4 ax-r2 df-a anor1 lor
    ) ABCZABDZEZABEZFZADZASFZEZFZRUCBFZUCSFZEZAUCBEZFZEZUFDZABGULUIDZUKDZFZDUMU
    IUKHUPUFUNUBUOUEUIUBUIUGDZUHDZFZDUBDUGUHHUSUBUQTURUAUGTABIJUAURABHKLMNJUKUE
    UKUCUJDZEZDUEDAUJOVAUEUTUDUCUDUTABPKQMNJLMNNJ $.
    $( [9-Nov-97] $)

  $( Identity for Kalmbach implication. $)
  i3id $p |- ( a ->3 a ) = 1 $=
    ( wn wa wo wi3 wt wf ancom dff ax-r1 ax-r2 anidm 2or ax-a2 or0 df-t lan
    an1 df-i3 3tr1 ) ABZACZUAUACZDZAUAADZCZDZAUADZAAEFUGUEUHUDUAUFAUDUAGDZUAUDG
    UADUIUBGUCUAUBAUACZGUAAHGUJAIJKUALMGUANKUAOKUFAFCAUEFAUEUHFUAANZFUHAPZJKQAR
    KMUKKAASULT $.
    $( [2-Nov-97] $)

  ${
    li3.1 $e |- a = b $.
    $( Introduce Kalmbach implication to the left. $)
    li3 $p |- ( c ->3 a ) = ( c ->3 b ) $=
      ( wn wa wo wi3 lan ax-r4 2or lor df-i3 3tr1 ) CEZAFZOAEZFZGZCOAGZFZGOBFZO
      BEZFZGZCOBGZFZGCAHCBHSUEUAUGPUBRUDABODIQUCOABDJIKTUFCABODLIKCAMCBMN $.
      $( [2-Nov-97] $)
  $}

  ${
    ri3.1 $e |- a = b $.
    $( Introduce Kalmbach implication to the right. $)
    ri3 $p |- ( a ->3 c ) = ( b ->3 c ) $=
      ( wn wa wo wi3 ax-r4 ran 2or ax-r5 2an df-i3 3tr1 ) AEZCFZPCEZFZGZAPCGZFZ
      GBEZCFZUCRFZGZBUCCGZFZGACHBCHTUFUBUHQUDSUEPUCCABDIZJPUCRUIJKABUAUGDPUCCUI
      LMKACNBCNO $.
      $( [2-Nov-97] $)
  $}

  ${
    2i3.1 $e |- a = b $.
    2i3.2 $e |- c = d $.
    $( Join both sides with Kalmbach implication. $)
    2i3 $p |- ( a ->3 c ) = ( b ->3 d ) $=
      ( wi3 li3 ri3 ax-r2 ) ACGADGBDGCDAFHABDEIJ $.
      $( [2-Nov-97] $)
  $}

  ${
    ud1lem0a.1 $e |- a = b $.
    $( Introduce ` ->1 ` to the left. $)
    ud1lem0a $p |- ( c ->1 a ) = ( c ->1 b ) $=
      ( wn wa wo wi1 lan lor df-i1 3tr1 ) CEZCAFZGMCBFZGCAHCBHNOMABCDIJCAKCBKL
      $.
      $( [23-Nov-97] $)

    $( Introduce ` ->1 ` to the right. $)
    ud1lem0b $p |- ( a ->1 c ) = ( b ->1 c ) $=
      ( wn wa wo wi1 ax-r4 ran 2or df-i1 3tr1 ) AEZACFZGBEZBCFZGACHBCHNPOQABDIA
      BCDJKACLBCLM $.
      $( [23-Nov-97] $)
  $}

  ${
    ud1lem0ab.1 $e |- a = b $.
    ud1lem0ab.2 $e |- c = d $.
    $( Join both sides of hypotheses with ` ->1 ` . $)
    ud1lem0ab $p |- ( a ->1 c ) = ( b ->1 d ) $=
      ( wi1 ud1lem0b ud1lem0a ax-r2 ) ACGBCGBDGABCEHCDBFIJ $.
      $( [19-Dec-98] $)
  $}

  ${
    ud2lem0a.1 $e |- a = b $.
    $( Introduce ` ->2 ` to the left. $)
    ud2lem0a $p |- ( c ->2 a ) = ( c ->2 b ) $=
      ( wn wa wo wi2 ax-r4 lan 2or df-i2 3tr1 ) ACEZAEZFZGBNBEZFZGCAHCBHABPRDOQ
      NABDIJKCALCBLM $.
      $( [23-Nov-97] $)

    $( Introduce ` ->2 ` to the right. $)
    ud2lem0b $p |- ( a ->2 c ) = ( b ->2 c ) $=
      ( wn wa wo wi2 ax-r4 ran lor df-i2 3tr1 ) CAEZCEZFZGCBEZOFZGACHBCHPRCNQOA
      BDIJKACLBCLM $.
      $( [23-Nov-97] $)
  $}

  ${
    ud3lem0a.1 $e |- a = b $.
    $( Introduce Kalmbach implication to the left. $)
    ud3lem0a $p |- ( c ->3 a ) = ( c ->3 b ) $=
      ( li3 ) ABCDE $.
      $( [23-Nov-97] $)

    $( Introduce Kalmbach implication to the right. $)
    ud3lem0b $p |- ( a ->3 c ) = ( b ->3 c ) $=
      ( ri3 ) ABCDE $.
      $( [23-Nov-97] $)
  $}

  ${
    ud4lem0a.1 $e |- a = b $.
    $( Introduce ` ->4 ` to the left. $)
    ud4lem0a $p |- ( c ->4 a ) = ( c ->4 b ) $=
      ( wa wn wo wi4 lan 2or lor ax-r4 2an df-i4 3tr1 ) CAEZCFZAEZGZQAGZAFZEZGC
      BEZQBEZGZQBGZBFZEZGCAHCBHSUEUBUHPUCRUDABCDIABQDIJTUFUAUGABQDKABDLMJCANCBN
      O $.
      $( [23-Nov-97] $)

    $( Introduce ` ->4 ` to the right. $)
    ud4lem0b $p |- ( a ->4 c ) = ( b ->4 c ) $=
      ( wa wn wo wi4 ran ax-r4 2or ax-r5 df-i4 3tr1 ) ACEZAFZCEZGZPCGZCFZEZGBCE
      ZBFZCEZGZUCCGZTEZGACHBCHRUEUAUGOUBQUDABCDIPUCCABDJZIKSUFTPUCCUHLIKACMBCMN
      $.
      $( [23-Nov-97] $)
  $}

  ${
    ud5lem0a.1 $e |- a = b $.
    $( Introduce ` ->5 ` to the left. $)
    ud5lem0a $p |- ( c ->5 a ) = ( c ->5 b ) $=
      ( wa wn wo wi5 lan 2or ax-r4 df-i5 3tr1 ) CAEZCFZAEZGZOAFZEZGCBEZOBEZGZOB
      FZEZGCAHCBHQUBSUDNTPUAABCDIABODIJRUCOABDKIJCALCBLM $.
      $( [23-Nov-97] $)

    $( Introduce ` ->5 ` to the right. $)
    ud5lem0b $p |- ( a ->5 c ) = ( b ->5 c ) $=
      ( wa wn wo wi5 ran ax-r4 2or df-i5 3tr1 ) ACEZAFZCEZGZOCFZEZGBCEZBFZCEZGZ
      UAREZGACHBCHQUCSUDNTPUBABCDIOUACABDJZIKOUARUEIKACLBCLM $.
      $( [23-Nov-97] $)
  $}

  $( Correspondence between Sasaki and Dishkant conditionals. $)
  i1i2 $p |- ( a ->1 b ) = ( b ' ->2 a ' ) $=
    ( wn wa wo wi1 wi2 ax-a1 2an ancom ax-r2 lor df-i1 df-i2 3tr1 ) ACZABDZEPBC
    ZCZPCZDZEABFRPGQUAPQTSDUAATBSAHBHITSJKLABMRPNO $.
    $( [25-Nov-98] $)

  $( Correspondence between Sasaki and Dishkant conditionals. $)
  i2i1 $p |- ( a ->2 b ) = ( b ' ->1 a ' ) $=
    ( wn wi2 wi1 ax-a1 ud2lem0b ud2lem0a i1i2 3tr1 ) ABCZCZDACZCZLDABDKMEANLAFG
    BLABFHKMIJ $.
    $( [7-Feb-99] $)

  $( Correspondence between Sasaki and Dishkant conditionals. $)
  i1i2con1 $p |- ( a ->1 b ' ) = ( b ->2 a ' ) $=
    ( wn wi1 wi2 i1i2 ax-a1 ax-r1 ud2lem0b ax-r2 ) ABCZDKCZACZEBMEAKFLBMBLBGHIJ
    $.
    $( [28-Feb-99] $)

  $( Correspondence between Sasaki and Dishkant conditionals. $)
  i1i2con2 $p |- ( a ' ->1 b ) = ( b ' ->2 a ) $=
    ( wn wi1 wi2 i1i2 ax-a1 ax-r1 ud2lem0a ax-r2 ) ACZBDBCZKCZELAEKBFMALAMAGHIJ
    $.
    $( [28-Feb-99] $)

  $( Correspondence between Kalmbach and non-tollens conditionals. $)
  i3i4 $p |- ( a ->3 b ) = ( b ' ->4 a ' ) $=
    ( wn wa wo wi3 wi4 ax-a2 ancom ax-a1 ran ax-r2 2or ax-r5 2an df-i3 df-i4
    3tr1 ) ACZBDZSBCZDZEZASBEZDZEUASDZUACZSDZEZUGSEZSCZDZEABFUASGUCUIUEULUCUBTE
    UITUBHUBUFTUHSUAITBSDUHSBIBUGSBJZKLMLUEUDADULAUDIUDUJAUKUDBSEUJSBHBUGSUMNLA
    JOLMABPUASQR $.
    $( [7-Feb-99] $)

  $( Correspondence between Kalmbach and non-tollens conditionals. $)
  i4i3 $p |- ( a ->4 b ) = ( b ' ->3 a ' ) $=
    ( wi4 wn wi3 ax-a1 ud4lem0a ud4lem0b ax-r2 i3i4 ax-r1 ) ABCZADZDZBDZDZCZOME
    ZLAPCQBPABFGANPAFHIRQOMJKI $.
    $( [7-Feb-99] $)

  $( Converse of ` ->5 ` . $)
  i5con $p |- ( a ->5 b ) = ( b ' ->5 a ' ) $=
    ( wa wn wo wi5 ancom ax-a2 ax-a1 ran ax-r2 2an 2or ax-a3 3tr1 df-i5 ) ABCZA
    DZBCZEZRBDZCZEZUARCZUADZRCZEUERDZCZEZABFUARFUBTEUDUFUHEZEUCUIUBUDTUJRUAGTSQ
    EUJQSHSUFQUHSBRCUFRBGBUERBIZJKQBACUHABGBUEAUGUKAILKMKMTUBHUDUFUHNOABPUARPO
    $.
    $( [7-Feb-99] $)

  $( Antecedent of 0 on Sasaki conditional. $)
  0i1 $p |- ( 0 ->1 a ) = 1 $=
    ( wf wi1 wn wa wo wt df-i1 ax-a2 df-f con2 lor ax-r2 or1 3tr ) BACBDZBAEZFZ
    QGFZGBAHRQPFSPQIPGQBGJKLMQNO $.
    $( [24-Dec-98] $)

  $( Antecedent of 1 on Sasaki conditional. $)
  1i1 $p |- ( 1 ->1 a ) = a $=
    ( wt wi1 wn wa wo df-i1 wf df-f ax-r1 ancom an1 ax-r2 2or ax-a2 or0 ) BACBD
    ZBAEZFZABAGSHAFZAQHRAHQIJRABEABAKALMNTAHFAHAOAPMMM $.
    $( [24-Dec-98] $)

  $( Identity law for Sasaki conditional. $)
  i1id $p |- ( a ->1 a ) = 1 $=
    ( wi1 wn wa wo wt df-i1 ax-a2 anidm lor df-t 3tr1 ax-r2 ) AABACZAADZEZFAAGN
    AEANEPFNAHOANAIJAKLM $.
    $( [25-Dec-98] $)

  $( Identity law for Dishkant conditional. $)
  i2id $p |- ( a ->2 a ) = 1 $=
    ( wi2 wn wa wo wt df-i2 anidm lor df-t ax-r1 ax-r2 ) AABAACZMDZEZFAAGOAMEZF
    NMAMHIFPAJKLL $.
    $( [26-Jun-03] $)

  $( Lemma for unified disjunction. $)
  ud1lem0c $p |- ( a ->1 b ) ' = ( a ^ ( a ' v b ' ) ) $=
    ( wi1 wn wo wa df-i1 df-a ax-r1 lor ax-r4 ax-r2 con3 con2 ) ABCZAADZBDEZFZO
    PABFZEZRDABGTRRTDZRPQDZEZDUAAQHUCTUBSPSUBABHIJKLIMLN $.
    $( [23-Nov-97] $)

  $( Lemma for unified disjunction. $)
  ud2lem0c $p |- ( a ->2 b ) ' = ( b ' ^ ( a v b ) ) $=
    ( wi2 wn wo wa df-i2 oran ax-r1 lan ax-r4 ax-r2 con2 ) ABCZBDZABEZFZNBADOFZ
    EZQDZABGSORDZFZDTBRHUBQUAPOPUAABHIJKLLM $.
    $( [23-Nov-97] $)

  $( Lemma for unified disjunction. $)
  ud3lem0c $p |- ( a ->3 b ) ' = ( ( ( a v b ' ) ^ ( a v b ) ) ^
                ( a ' v ( a ^ b ' ) ) ) $=
    ( ni31 ) ABC $.
    $( [22-Nov-97] $)

  $( Lemma for unified disjunction. $)
  ud4lem0c $p |- ( a ->4 b ) ' = ( ( ( a ' v b ' ) ^ ( a v b ' ) ) ^
                ( ( a ^ b ' ) v b ) ) $=
    ( wi4 wn wo wa df-i4 oran df-a con2 anor2 2an ax-r4 ax-r2 anor1 ax-r1
    ax-r5 ) ABCZADZBDZEZATEZFZATFZBEZFZRABFZSBFZEZSBEZTFZEZUFDZABGULUIDZUKDZFZD
    UMUIUKHUPUFUNUCUOUEUIUCUIUGDZUHDZFZDUCDUGUHHUSUCUQUAURUBUGUAABIJUHUBABKJLMN
    JUKUEUKUJDZBEZDUEDUJBOVAUEUTUDBUDUTABOPQMNJLMNNJ $.
    $( [23-Nov-97] $)

  $( Lemma for unified disjunction. $)
  ud5lem0c $p |- ( a ->5 b ) ' = ( ( ( a ' v b ' ) ^ ( a v b ' ) ) ^
                ( a v b ) ) $=
    ( wi5 wn wo wa df-i5 oran df-a con2 anor2 2an ax-r4 ax-r2 ax-r1 ) ABCZADZBD
    ZEZAREZFZABEZFZPABFZQBFZEZQRFZEZUCDZABGUHUFDZUGDZFZDUIUFUGHULUCUJUAUKUBUFUA
    UFUDDZUEDZFZDUADUDUEHUOUAUMSUNTUDSABIJUETABKJLMNJUBUKABHOLMNNJ $.
    $( [23-Nov-97] $)

  $( Pavicic binary logic ax-a1 analog. $)
  bina1 $p |- ( a ->3 a ' ' ) = 1 $=
    ( wi3 wn i3id ax-a1 li3 bi1 wwbmp ) AABZAACCZBZADIKAJAAEFGH $.
    $( [5-Nov-97] $)

  $( Pavicic binary logic ax-a2 analog. $)
  bina2 $p |- ( a ' ' ->3 a ) = 1 $=
    ( wi3 wn i3id ax-a1 ri3 bi1 wwbmp ) AABZACCZABZADIKAJAAEFGH $.
    $( [5-Nov-97] $)

  $( Pavicic binary logic ax-a3 analog. $)
  bina3 $p |- ( a ->3 ( a v b ) ) = 1 $=
    ( wo leo lei3 ) AABCABDE $.
    $( [5-Nov-97] $)

  $( Pavicic binary logic ax-a4 analog. $)
  bina4 $p |- ( b ->3 ( a v b ) ) = 1 $=
    ( wo leo ax-a2 lbtr lei3 ) BABCZBBACHBADBAEFG $.
    $( [5-Nov-97] $)

  $( Pavicic binary logic ax-a5 analog. $)
  bina5 $p |- ( b ->3 ( a v a ' ) ) = 1 $=
    ( wn wo wt le1 df-t lbtr lei3 ) BAACDZBEJBFAGHI $.
    $( [5-Nov-97] $)

  ${
    wql1lem.1 $e |- ( a ->1 b ) = 1 $.
    $( Classical implication inferred from Sakaki implication. $)
    wql1lem $p |- ( a ' v b ) = 1 $=
      ( wn wo wt le1 wi1 ax-r1 wa df-i1 lear lelor bltr lebi ) ADZBEZFQGFABHZQR
      FCIRPABJZEQABKSBPABLMNNO $.
      $( [5-Dec-98] $)
  $}

  ${
    wql2lem.1 $e |- ( a ->2 b ) = 1 $.
    $( Classical implication inferred from Dishkant implication. $)
    wql2lem $p |- ( a ' v b ) = 1 $=
      ( wn wo wt le1 wa wi2 df-i2 ax-a2 3tr2 lea leror bltr lebi ) ADZBEZFRGFQB
      DZHZBEZRABIBTEFUAABJCBTKLTQBQSMNOP $.
      $( [6-Dec-98] $)
  $}

  ${
    wql2lem2.1 $e |- ( ( a v c ) ->2 ( b v c ) ) = 1 $.
    $( Lemma for ` ->2 ` WQL axiom. $)
    wql2lem2 $p |- ( ( a v ( b v c ) ) ' v ( b v c ) ) = 1 $=
      ( wo wn wi2 wt wa df-i2 anor3 ax-a3 ax-r1 orordir ax-r2 ax-r4 lor ax-a2
      3tr ) ABCEZEZFZTEZACEZTGZHUEUCUETUDFTFIZETUBEUCUDTJUFUBTUFUDTEZFZUBUDTKUB
      UHUAUGUAABECEZUGUIUAABCLMABCNOPMOQTUBRSMDO $.
      $( [6-Dec-98] $)
  $}

  ${
    wql2lem3.1 $e |- ( a ->2 b ) = 1 $.
    $( Lemma for ` ->2 ` WQL axiom. $)
    wql2lem3 $p |- ( ( a ^ b ' ) ->2 a ' ) = 1 $=
      ( wn wa wi2 wo wt df-i2 oran2 ax-r1 ran ancom ax-r2 lor wql2lem omlem2
      skr0 3tr ) ABDEZADZFUATDZUADZEZGUAUCUABGZEZGZHTUAIUDUFUAUDUEUCEUFUBUEUCUE
      UBABJKLUEUCMNOUEUGABCPUABQRS $.
      $( [6-Dec-98] $)
  $}

  ${
    wql2lem4.1 $e |- ( ( ( a ^ b ' ) v ( a ^ b ) ) ->2
                     ( a ' v ( a ^ b ) ) ) = 1 $.
    wql2lem4.2 $e |- ( ( a ->1 b ) v ( a ^ b ' ) ) = 1 $.
    $( Lemma for ` ->2 ` WQL axiom. $)
    wql2lem4 $p |- ( a ->1 b ) = 1 $=
      ( wi1 wn wa wo wt df-i1 id ax-a2 ax-r5 ax-r1 3tr wql2lem2 skr0 ) ABEZAFZA
      BGZHZUAIABJZUAKABFGZUAHZUAUDUAUCHZRUCHZIUCUALUFUERUAUCUBMNDOUCSTCPQO $.
      $( [6-Dec-98] $)
  $}

  ${
    wql2lem5.1 $e |- ( a ->2 b ) = 1 $.
    $( Lemma for ` ->2 ` WQL axiom. $)
    wql2lem5 $p |- ( ( b ' ^ ( a v b ) ) ->2 a ' ) = 1 $=
      ( wn wo wa wi2 wt anor3 oran3 ud2lem0c ax-r5 ran ancom an1 3tr ax-r4
      3tr2 ax-r2 lor df-i2 df-t 3tr1 ) ADZBDABEFZDUDDZFZEUDUFEUEUDGHUGUFUDUGUEU
      DEZDUFUEUDIUHUDABGZDZUDEUIAFZDUHUDUIAJUJUEUDABKLUKAUKHAFAHFAUIHACMHANAOPQ
      RQSTUEUDUAUDUBUC $.
      $( [6-Dec-98] $)
  $}


  ${
    wql1.1 $e |- ( a ->1 b ) = 1 $.
    wql1.2 $e |- ( ( a v c ) ->1 ( b v c ) ) = 1 $.
    wql1.3 $e |- c = b $.
    $( The 2nd hypothesis is the first ` ->1 ` WQL axiom.  We show it
       implies the WOM law. $)
    wql1 $p |- ( a ->2 b ) = 1 $=
      ( wi2 wn wa wo wt df-i2 anor3 lor ax-a2 wi1 oridm ax-r2 ud1lem0a ax-r1
      ud1lem0b 3tr2 wql1lem 3tr ) ABGBAHBHIZJBABJZHZJZKABLUEUGBABMNUHUGBJKBUGOU
      FBACJZBPZUIBCJZPZUFBPKULUJUKBUIUKBBJBCBBFNBQRSTUIUFBCBAFNUAEUBUCRUD $.
      $( [5-Dec-98] $)
  $}

  ${
    oaidlem1.1 $e |- ( a ^ b ) =< c $.
    $( Lemma for OA identity-like law. $)
    oaidlem1 $p |- ( a ' v ( b ->1 c ) ) = 1 $=
      ( wn wi1 wo wa wt df-i1 lor oran3 ax-r5 ax-a3 lear ler2an sklem 3tr2
      ax-r2 ) AEZBCFZGTBEZBCHZGZGZIUAUDTBCJKTUBGZUCGABHZEZUCGUEIUFUHUCABLMTUBUC
      NUGUCUGBCABODPQRS $.
      $( [22-Jan-99] $)
  $}


  ${
    womle2a.1 $e |- ( a ^ ( a ->2 b ) ) =<
                   ( ( a ->2 b ) ' v ( a ->1 b ) ) $.
    $( An equivalent to the WOM law. $)
    womle2a $p |- ( ( a ->2 b ) ' v ( a ->1 b ) ) = 1 $=
      ( wi2 wn wi1 wo wa wt or4 oridm df-i1 ax-r5 or32 3tr1 ax-r2 2or ax-a2
      oran3 lor 3tr2 le1 df-t leror bltr lebi ) ABDZEZABFZGZUJAUGHZEZGZIUHUHGZU
      IAEZGZGUJUHUOGZGUJUMUHUHUIUOJUNUHUPUIUHKUPUOABHZGZUOGZUIUIUSUOABLZMUOUOGZ
      URGUSUTUIVBUOURUOKMUOURUONVAOPQUQULUJUQUOUHGULUHUORAUGSPTUAUMIUMUBIUKULGU
      MUKUCUKUJULCUDUEUFP $.
      $( [24-Jan-99] $)
  $}

  ${
    womle2b.1 $e |- ( ( a ->2 b ) ' v ( a ->1 b ) ) = 1 $.
    $( An equivalent to the WOM law. $)
    womle2b $p |- ( a ^ ( a ->2 b ) ) =<
                   ( ( a ->2 b ) ' v ( a ->1 b ) ) $=
      ( wi2 wa wt wn wi1 wo le1 ax-r1 lbtr ) AABDZEZFMGABHIZNJOFCKL $.
      $( [24-Jan-99] $)
  $}

  ${
    womle3b.1 $e |- ( ( a ->1 b ) ' v ( a ->2 b ) ) = 1 $.
    $( Implied by the WOM law. $)
    womle3b $p |- ( a ^ ( a ->1 b ) ) =<
                   ( ( a ->1 b ) ' v ( a ->2 b ) ) $=
      ( wi1 wa wt wn wi2 wo le1 ax-r1 lbtr ) AABDZEZFMGABHIZNJOFCKL $.
      $( [27-Jan-99] $)
  $}

  ${
    womle.1 $e |- ( a ^ ( a ->1 b ) ) = ( a ^ ( a ->2 b ) ) $.
    $( An equality implying the WOM law. $)
    womle $p |- ( ( a ->2 b ) ' v ( a ->1 b ) ) = 1 $=
      ( wi2 wa wi1 wn wo ax-r1 lear bltr leor letr womle2a ) ABAABDZEZABFZOGZQH
      PAQEZQSPCIAQJKQRLMN $.
      $( [24-Jan-99] $)
  $}

  $( Lemma for "Non-Orthomodular Models..." paper. $)
  nomb41 $p |- ( a ==4 b ) = ( b ==1 a ) $=
    ( wn wo wa wid4 wid1 ax-a2 ancom lor 2an df-id4 df-id1 3tr1 ) ACZBDZBCZABEZ
    DZEBODZQBAEZDZEABFBAGPTSUBOBHRUAQABIJKABLBAMN $.
    $( [7-Feb-99] $)

  $( Lemma for "Non-Orthomodular Models..." paper. $)
  nomb32 $p |- ( a ==3 b ) = ( b ==2 a ) $=
    ( wn wo wa wid3 wid2 ax-a2 ancom lor 2an df-id3 df-id2 3tr1 ) ACZBDZAOBCZEZ
    DZEBODZAQOEZDZEABFBAGPTSUBOBHRUAAOQIJKABLBAMN $.
    $( [7-Feb-99] $)

  $( Lemma for "Non-Orthomodular Models..." paper. $)
  nomcon0 $p |- ( a ==0 b ) = ( b ' ==0 a ' ) $=
    ( wn wo wa wid0 ax-a2 ax-a1 ax-r5 ax-r2 2an df-id0 3tr1 ) ACZBDZBCZADZEPCZN
    DZNCZPDZEABFPNFOSQUAOBNDSNBGBRNBHIJQAPDUAPAGATPAHIJKABLPNLM $.
    $( [7-Feb-99] $)

  $( Lemma for "Non-Orthomodular Models..." paper. $)
  nomcon1 $p |- ( a ==1 b ) = ( b ' ==2 a ' ) $=
    ( wn wo wa wid1 wid2 ax-a2 ax-a1 lor ax-r2 ancom 2an df-id1 df-id2 3tr1 )
    ABCZDZACZABEZDZEQSCZDZSQCZUBEZDZEABFQSGRUCUAUFRQADUCAQHAUBQAIZJKTUESTBAEUEA
    BLBUDAUBBIUGMKJMABNQSOP $.
    $( [7-Feb-99] $)

  $( Lemma for "Non-Orthomodular Models..." paper. $)
  nomcon2 $p |- ( a ==2 b ) = ( b ' ==1 a ' ) $=
    ( wn wo wa wid2 wid1 ax-a2 ax-a1 lor ax-r2 ancom 2or 2an df-id2 df-id1
    3tr1 ) ABCZDZBACZREZDZERTCZDZRCZRTEZDZEABFRTGSUDUBUGSRADUDARHAUCRAIJKBUEUAU
    FBITRLMNABORTPQ $.
    $( [7-Feb-99] $)

  $( Lemma for "Non-Orthomodular Models..." paper. $)
  nomcon3 $p |- ( a ==3 b ) = ( b ' ==4 a ' ) $=
    ( wid2 wn wid1 wid3 wid4 nomcon2 nomb32 nomb41 3tr1 ) BACADZBDZEABFMLGBAHAB
    IMLJK $.
    $( [7-Feb-99] $)

  $( Lemma for "Non-Orthomodular Models..." paper. $)
  nomcon4 $p |- ( a ==4 b ) = ( b ' ==3 a ' ) $=
    ( wid1 wn wid2 wid4 wid3 nomcon1 nomb41 nomb32 3tr1 ) BACADZBDZEABFMLGBAHAB
    IMLJK $.
    $( [7-Feb-99] $)

  $( Lemma for "Non-Orthomodular Models..." paper. $)
  nomcon5 $p |- ( a == b ) = ( b ' == a ' ) $=
    ( tb wn bicom conb ax-r2 ) ABCBACBDADCABEBAFG $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom10 $p |- ( a ->0 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wn wa wo wi0 wi1 id df-i0 df-i1 3tr1 ) ACABDZEZMALFABGMHALIABJK $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom11 $p |- ( a ->1 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wn wa wo wi1 anass ax-r1 anidm ran ax-r2 lor df-i1 3tr1 ) ACZAABDZDZEOPEA
    PFABFQPOQAADZBDZPSQAABGHRABAIJKLAPMABMN $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom12 $p |- ( a ->2 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wa wn wo wi2 wi1 oran ax-r1 a5b ax-r2 con3 lor ax-a2 df-i2 df-i1 3tr1 )
    ABCZADZRDCZEZSREZARFABGUARSEUBTSRTATDZAREZAUDUCARHIABJKLMRSNKAROABPQ $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom13 $p |- ( a ->3 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wn wa wo wi3 wi1 oran ax-r1 a5b ax-r2 con3 lor lea df-le2 ax-r5 womaa
    df-i3 df-i1 3tr1 ) ACZABDZDZUAUBCDZEZAUAUBEZDZEZUFAUBFABGUHUAUGEUFUEUAUGUEU
    CUAEUAUDUAUCUDAUDCZAUBEZAUJUIAUBHIABJKLMUCUAUAUBNOKPABQKAUBRABST $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom14 $p |- ( a ->4 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wa wn wo wi4 wi1 ax-a2 anass ax-r1 anidm ran ax-r2 lor lear df-le2 3tr
    ax-r5 leo lea lbtr lel2or lecon ler2an lelor lebi df-i4 df-i1 3tr1 ) AABCZC
    ZADZUJCZEZULUJEZUJDZCZEZUOAUJFABGURUJUQEZUJULEZUOUNUJUQUNUMUKEUMUJEUJUKUMHU
    KUJUMUKAACZBCZUJVBUKAABIJVAABAKLMNUMUJULUJOPQRUSUTUJUTUQUJULSUQUOUTUOUPTULU
    JHUAUBULUQUJULUOUPULUJSUJAABTUCUDUEUFUJULHQAUJUGABUHUI $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom15 $p |- ( a ->5 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wa wn wo wi5 wi1 anass ax-r1 anidm ran ax-r2 ax-r5 ax-a2 lear df-le2 3tr
    oran3 lan a5c 2or df-i5 df-i1 3tr1 ) AABCZCZADZUECZEZUGUEDZCZEZUGUEEZAUEFAB
    GULUEUGEUMUIUEUKUGUIUEUHEUHUEEUEUFUEUHUFAACZBCZUEUOUFAABHIUNABAJKLMUEUHNUHU
    EUGUEOPQUKUGUGBDZEZCZUGURUKUQUJUGABRSIUGUPTLUAUEUGNLAUEUBABUCUD $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom20 $p |- ( a ==0 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wn wa wo wid0 wi1 lea leor letr lelor ax-a3 ax-r1 oran3 ax-r5 ax-r2 lbtr
    df2le2 df-id0 df-i1 3tr1 ) ACZABDZEZUCCZAEZDUDAUCFABGUDUFUDUBBCZAEZEZUFUCUH
    UBUCAUHABHAUGIJKUIUBUGEZAEZUFUKUIUBUGALMUJUEAABNOPQRAUCSABTUA $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom21 $p |- ( a ==1 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wa wn wo wid1 wi1 ancom or12 oran3 lor ax-r2 anidm ran ax-r1 anass 2an
    lea leo letr lelor df2le2 3tr2 df-id1 df-i1 3tr1 ) AABCZDZEZADZAUGCZEZCZUJU
    GEZAUGFABGUJABDZEZEZUNCUNUQCUMUNUQUNHUQUIUNULUQAUJUOEZEUIUJAUOIURUHAABJKLUG
    UKUJUGAACZBCZUKUTUGUSABAMNOAABPLKQUNUQUGUPUJUGAUPABRAUOSTUAUBUCAUGUDABUEUF
    $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom22 $p |- ( a ==2 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wa wn wo wid2 wi1 oran3 lor ax-r1 or12 ax-r2 ax-a2 lan a5c ax-r5 2an
    ancom lea leo letr lelor df2le2 3tr df-id2 df-i1 3tr1 ) AABCZDZEZUHADZUICZE
    ZCZUKUHEZAUHFABGUNUKABDZEZEZUOCUOURCUOUJURUMUOUJAUKUPEZEZURUTUJUSUIAABHZIJA
    UKUPKLUMULUHEUOUHULMULUKUHULUKUSCZUKVBULUSUIUKVANJUKUPOLPLQURUORUOURUHUQUKU
    HAUQABSAUPTUAUBUCUDAUHUEABUFUG $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom23 $p |- ( a ==3 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wn wa wo wid3 wi1 wt le1 df-t a5c ax-r1 oran3 lan ax-r2 lor lbtr df2le2
    df-id3 df-i1 3tr1 ) ACZABDZEZAUBUCCZDZEZDUDAUCFABGUDUGUDHUGUDIHAUBEUGAJUBUF
    AUBUBUBBCZEZDZUFUJUBUBUHKLUIUEUBABMNOPOQRAUCSABTUA $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom24 $p |- ( a ==4 ( a ^ b ) ) = ( a ->1 b ) $=
    ( wn wa wo wid4 wi1 leo leror oran3 anidm ran ax-r1 anass ax-r2 2or lbtr
    df2le2 df-id4 df-i1 3tr1 ) ACZABDZEZUCCZAUCDZEZDUDAUCFABGUDUGUDUBBCZEZUCEUG
    UBUIUCUBUHHIUIUEUCUFABJUCAADZBDZUFUKUCUJABAKLMAABNOPQRAUCSABTUA $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom25 $p |- ( a == ( a ^ b ) ) = ( a ->1 b ) $=
    ( wa wn wo tb wi1 anass ax-r1 anidm ran ax-r2 oran3 lan a5c 2or ax-a2 dfb
    df-i1 3tr1 ) AABCZCZADZUADZCZEZUCUAEZAUAFABGUFUAUCEUGUBUAUEUCUBAACZBCZUAUIU
    BAABHIUHABAJKLUEUCUCBDZEZCZUCULUEUKUDUCABMNIUCUJOLPUAUCQLAUARABST $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom30 $p |- ( ( a ^ b ) ==0 a ) = ( a ->1 b ) $=
    ( wa wid0 wi1 wn wo ancom df-id0 3tr1 nom20 ax-r2 ) ABCZADZAMDZABEMFAGZAFMG
    ZCQPCNOPQHMAIAMIJABKL $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom31 $p |- ( ( a ^ b ) ==1 a ) = ( a ->1 b ) $=
    ( wa wid1 wid4 wi1 nomb41 ax-r1 nom24 ax-r2 ) ABCZADZAKEZABFMLAKGHABIJ $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom32 $p |- ( ( a ^ b ) ==2 a ) = ( a ->1 b ) $=
    ( wa wid2 wid3 wi1 nomb32 ax-r1 nom23 ax-r2 ) ABCZADZAKEZABFMLAKGHABIJ $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom33 $p |- ( ( a ^ b ) ==3 a ) = ( a ->1 b ) $=
    ( wa wid3 wid2 wi1 nomb32 nom22 ax-r2 ) ABCZADAJEABFJAGABHI $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom34 $p |- ( ( a ^ b ) ==4 a ) = ( a ->1 b ) $=
    ( wa wid4 wid1 wi1 nomb41 nom21 ax-r2 ) ABCZADAJEABFJAGABHI $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(14) from "Non-Orthomodular Models..." paper. $)
  nom35 $p |- ( ( a ^ b ) == a ) = ( a ->1 b ) $=
    ( wa tb wi1 bicom nom25 ax-r2 ) ABCZADAIDABEIAFABGH $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom40 $p |- ( ( a v b ) ->0 b ) = ( a ->2 b ) $=
    ( wn wa wi0 wi1 wo wi2 nom10 ax-a2 ax-a1 ancom anor3 ax-r2 ax-r1 2or df-i0
    3tr1 i2i1 ) BCZTACZDZEZTUAFABGZBEZABHTUAIUDCZBGZTCZUBGZUEUCUGBUFGUIUFBJBUHU
    FUBBKUBUFUBUATDUFTUALABMNOPNUDBQTUBQRABSR $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom41 $p |- ( ( a v b ) ->1 b ) = ( a ->2 b ) $=
    ( wn wo wi2 wi1 wa ancom anor3 ax-r2 ud2lem0a ax-r1 nom12 i1i2 i2i1 3tr1 )
    BCZABDZCZEZQACZFZRBFABETQQUAGZEZUBUDTUCSQUCUAQGSQUAHABIJKLQUAMJRBNABOP $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom42 $p |- ( ( a v b ) ->2 b ) = ( a ->2 b ) $=
    ( wn wo wi1 wi2 wa ancom anor3 ax-r2 ud1lem0a ax-r1 nom11 i2i1 3tr1 ) BCZAB
    DZCZEZPACZEZQBFABFSPPTGZEZUAUCSUBRPUBTPGRPTHABIJKLPTMJQBNABNO $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom43 $p |- ( ( a v b ) ->3 b ) = ( a ->2 b ) $=
    ( wn wo wi4 wi1 wi3 wi2 wa ancom anor3 ax-r2 ud4lem0a ax-r1 nom14 i3i4
    i2i1 3tr1 ) BCZABDZCZEZSACZFZTBGABHUBSSUCIZEZUDUFUBUEUASUEUCSIUASUCJABKLMNS
    UCOLTBPABQR $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom44 $p |- ( ( a v b ) ->4 b ) = ( a ->2 b ) $=
    ( wn wo wi3 wi1 wi4 wi2 wa ancom anor3 ax-r2 ud3lem0a ax-r1 nom13 i4i3
    i2i1 3tr1 ) BCZABDZCZEZSACZFZTBGABHUBSSUCIZEZUDUFUBUEUASUEUCSIUASUCJABKLMNS
    UCOLTBPABQR $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom45 $p |- ( ( a v b ) ->5 b ) = ( a ->2 b ) $=
    ( wn wo wi5 wi1 wi2 wa ancom anor3 ax-r2 ud5lem0a ax-r1 nom15 i5con i2i1
    3tr1 ) BCZABDZCZEZRACZFZSBEABGUARRUBHZEZUCUEUAUDTRUDUBRHTRUBIABJKLMRUBNKSBO
    ABPQ $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom50 $p |- ( ( a v b ) ==0 b ) = ( a ->2 b ) $=
    ( wn wo wid0 wi1 wi2 wa ancom anor3 ax-r2 lor ax-r4 ax-r5 2an ax-r1 df-id0
    3tr1 nom20 nomcon0 i2i1 ) BCZABDZCZEZUBACZFZUCBEABGUEUBUBUFHZEZUGUBCZUDDZUD
    CZUBDZHZUJUHDZUHCZUBDZHZUEUIURUNUOUKUQUMUHUDUJUHUFUBHUDUBUFIABJKZLUPULUBUHU
    DUSMNOPUBUDQUBUHQRUBUFSKUCBTABUAR $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom51 $p |- ( ( a v b ) ==1 b ) = ( a ->2 b ) $=
    ( wn wo wid2 wi1 wid1 wi2 wa ancom anor3 ax-r2 ax-r1 ax-r4 lor lan 2or 2an
    df-id2 3tr1 nom22 nomcon1 i2i1 ) BCZABDZCZEZUDACZFZUEBGABHUGUDUDUHIZEZUIUDU
    FCZDZUFUDCZULIZDZIUDUJCZDZUJUNUQIZDZIUGUKUMURUPUTULUQUDUFUJUJUFUJUHUDIZUFUD
    UHJABKZLMZNOUFUJUOUSVCULUQUNUFUJUFVAUJVAUFVBMUHUDJLNPQRUDUFSUDUJSTUDUHUALUE
    BUBABUCT $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom52 $p |- ( ( a v b ) ==2 b ) = ( a ->2 b ) $=
    ( wn wo wid1 wi1 wid2 wi2 wa ancom anor3 ax-r2 ax-r1 ax-r4 lor lan 2an
    df-id1 3tr1 nom21 nomcon2 i2i1 ) BCZABDZCZEZUCACZFZUDBGABHUFUCUCUGIZEZUHUCU
    ECZDZUCCZUCUEIZDZIUCUICZDZUMUCUIIZDZIUFUJULUQUOUSUKUPUCUEUIUIUEUIUGUCIUEUCU
    GJABKLMZNOUNURUMUEUIUCUTPOQUCUERUCUIRSUCUGTLUDBUAABUBS $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom53 $p |- ( ( a v b ) ==3 b ) = ( a ->2 b ) $=
    ( wn wo wid4 wi1 wid3 wi2 wa ancom anor3 ax-r2 ax-r1 lor ax-r4 lan 2or 2an
    df-id4 3tr1 nom24 nomcon3 i2i1 ) BCZABDZCZEZUDACZFZUEBGABHUGUDUDUHIZEZUIUDC
    ZUFDZUFCZUDUFIZDZIULUJDZUJCZUDUJIZDZIUGUKUMUQUPUTUFUJULUJUFUJUHUDIUFUDUHJAB
    KLMZNUNURUOUSUFUJVAOUFUJUDVAPQRUDUFSUDUJSTUDUHUALUEBUBABUCT $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom54 $p |- ( ( a v b ) ==4 b ) = ( a ->2 b ) $=
    ( wn wo wid3 wi1 wid4 wi2 wa ancom anor3 ax-r2 lor ax-r4 lan 2an df-id3
    3tr1 ax-r1 nom23 nomcon4 i2i1 ) BCZABDZCZEZUCACZFZUDBGABHUFUCUCUGIZEZUHUJUF
    UCCZUIDZUCUKUICZIZDZIUKUEDZUCUKUECZIZDZIUJUFULUPUOUSUIUEUKUIUGUCIUEUCUGJABK
    LZMUNURUCUMUQUKUIUEUTNOMPUCUIQUCUEQRSUCUGTLUDBUAABUBR $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom55 $p |- ( ( a v b ) == b ) = ( a ->2 b ) $=
    ( wn wa tb wi1 wo wi2 nom25 conb bicom ancom anor3 ax-r2 ax-r1 lbi 3tr
    i2i1 3tr1 ) BCZTACZDZEZTUAFABGZBEZABHTUAIUEUDCZTETUFEUCUDBJUFTKUFUBTUBUFUBU
    ATDUFTUALABMNOPQABRS $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom60 $p |- ( b ==0 ( a v b ) ) = ( a ->2 b ) $=
    ( wo wid0 wi2 wn wa ancom df-id0 3tr1 nom50 ax-r2 ) BABCZDZMBDZABEBFMCZMFBC
    ZGQPGNOPQHBMIMBIJABKL $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom61 $p |- ( b ==1 ( a v b ) ) = ( a ->2 b ) $=
    ( wo wid1 wid4 wi2 nomb41 ax-r1 nom54 ax-r2 ) BABCZDZKBEZABFMLKBGHABIJ $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom62 $p |- ( b ==2 ( a v b ) ) = ( a ->2 b ) $=
    ( wo wid2 wid3 wi2 nomb32 ax-r1 nom53 ax-r2 ) BABCZDZKBEZABFMLKBGHABIJ $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom63 $p |- ( b ==3 ( a v b ) ) = ( a ->2 b ) $=
    ( wo wid3 wid2 wi2 nomb32 nom52 ax-r2 ) BABCZDJBEABFBJGABHI $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom64 $p |- ( b ==4 ( a v b ) ) = ( a ->2 b ) $=
    ( wo wid4 wid1 wi2 nomb41 nom51 ax-r2 ) BABCZDJBEABFBJGABHI $.
    $( [7-Feb-99] $)

  $( Part of Lemma 3.3(15) from "Non-Orthomodular Models..." paper. $)
  nom65 $p |- ( b == ( a v b ) ) = ( a ->2 b ) $=
    ( wo tb wi2 bicom nom55 ax-r2 ) BABCZDIBDABEBIFABGH $.
    $( [7-Feb-99] $)

  $( Lemma for proof of Mayet 8-variable "full" equation from 4-variable
     Godowski equation. $)
  go1 $p |- ( ( a ^ b ) ^ ( a ->1 b ' ) ) = 0 $=
    ( wa wn wi1 wo wf df-i1 lan lear lelor lelan oran3 dff ax-r1 ax-r2 lbtr
    le0 lebi ) ABCZABDZEZCTADZAUACZFZCZGUBUETAUAHIUFGUFTUCUAFZCZGUEUGTUDUAUCAUA
    JKLUHTTDZCZGUGUITABMIGUJTNOPQUFRSP $.
    $( [19-Nov-99] $)

  $( Lemma for disjunction of ` ->2 ` . $)
  i2or $p |- ( ( a ->2 c ) v ( b ->2 c ) ) =< ( ( a ^ b ) ->2 c ) $=
    ( wi2 wo wa wn df-i2 lea lecon leran lelor bltr lear lel2or ax-r1 lbtr ) AC
    DZBCDZECABFZGZCGZFZEZTCDZRUDSRCAGZUBFZEUDACHUGUCCUFUAUBTAABIJKLMSCBGZUBFZEU
    DBCHUIUCCUHUAUBTBABNJKLMOUEUDTCHPQ $.
    $( [5-Jul-00] $)

  $( Lemma for disjunction of ` ->1 ` . $)
  i1or $p |- ( ( c ->1 a ) v ( c ->1 b ) ) =< ( c ->1 ( a v b ) ) $=
    ( wi1 wo wn wa df-i1 leo lelan lelor bltr leor lel2or ax-r1 lbtr ) CADZCBDZ
    ECFZCABEZGZEZCTDZQUBRQSCAGZEUBCAHUDUASATCABIJKLRSCBGZEUBCBHUEUASBTCBAMJKLNU
    CUBCTHOP $.
    $( [5-Jul-00] $)

  $( "Less than" analogue is equal to ` ->2 ` implication. $)
  lei2 $p |- ( a =<2 b ) = ( a ->2 b ) $=
    ( wo tb wn wa wle2 wi2 mi df-le df-i2 3tr1 ) ABCBDBAEBEFCABGABHABIABJABKL
    $.
    $( [28-Jan-02] $)

  $( Relevance implication is l.e. Sasaki implication. $)
  i5lei1 $p |- ( a ->5 b ) =< ( a ->1 b ) $=
    ( wa wn wo wi5 wi1 ax-a3 ax-a2 ax-r2 lea lel2or leror bltr df-i5 df-i1
    le3tr1 ) ABCZADZBCZESBDZCZEZSREZABFABGUCTUBEZREZUDUCRUEEUFRTUBHRUEIJUESRTSU
    BSBKSUAKLMNABOABPQ $.
    $( [26-Jun-03] $)

  $( Relevance implication is l.e. Dishkant implication. $)
  i5lei2 $p |- ( a ->5 b ) =< ( a ->2 b ) $=
    ( wa wn wo wi5 wi2 lear lel2or leror df-i5 df-i2 le3tr1 ) ABCZADZBCZEZOBDCZ
    EBREABFABGQBRNBPABHOBHIJABKABLM $.
    $( [26-Jun-03] $)

  $( Relevance implication is l.e. Kalmbach implication. $)
  i5lei3 $p |- ( a ->5 b ) =< ( a ->3 b ) $=
    ( wa wn wo wi5 wi3 leor lelan leror df-i5 ax-a3 ax-r2 df-i3 ax-a2 le3tr1 )
    ABCZADZBCZRBDCZEZEZARBEZCZUAEZABFZABGZQUDUABUCABRHIJUFQSETEUBABKQSTLMUGUAUD
    EUEABNUAUDOMP $.
    $( [26-Jun-03] $)

  $( Relevance implication is l.e. non-tollens implication. $)
  i5lei4 $p |- ( a ->5 b ) =< ( a ->4 b ) $=
    ( wa wn wo wi5 wi4 leo leran lelor df-i5 df-i4 le3tr1 ) ABCADZBCEZNBDZCZEON
    BEZPCZEABFABGQSONRPNBHIJABKABLM $.
    $( [26-Jun-03] $)

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
          Weak Orthomodular Law
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  ${
    ax-wom.1 $e |- ( a ' v ( a ^ b ) ) = 1 $.
    $( 2-variable WOML rule. $)
    ax-wom   $a |- ( b v ( a ' ^ b ' ) ) = 1 $.
  $}

  ${
    2vwomr2.1 $e |- ( b v ( a ' ^ b ' ) ) = 1 $.
    $( 2-variable WOML rule. $)
    2vwomr2   $p |- ( a ' v ( a ^ b ) ) = 1 $=
      ( wn wa wo wt ancom ax-a1 2an ax-r2 lor 2or ax-r1 ax-wom ) ADZABEZFPBDZDZ
      PDZEZFGQUAPQBAEUAABHBSATBIZAIJKLRPSRPEZFZBPREZFZGUFUDBSUEUCUBPRHMNCKOK $.
      $( [13-Nov-98] $)
  $}

  ${
    2vwomr1a.1 $e |- ( a ->1 b ) = 1 $.
    $( 2-variable WOML rule. $)
    2vwomr1a   $p |- ( a ->2 b ) = 1 $=
      ( wi2 wn wa wo wt df-i2 wi1 df-i1 ax-r1 ax-r2 ax-wom ) ABDBAEZBEFGHABIABO
      ABFGZABJZHQPABKLCMNM $.
      $( [13-Nov-98] $)
  $}

  ${
    2vwomr2a.1 $e |- ( a ->2 b ) = 1 $.
    $( 2-variable WOML rule. $)
    2vwomr2a   $p |- ( a ->1 b ) = 1 $=
      ( wi1 wn wa wo wt df-i1 wi2 df-i2 ax-r1 ax-r2 2vwomr2 ) ABDAEZABFGHABIABB
      OBEFGZABJZHQPABKLCMNM $.
      $( [13-Nov-98] $)
  $}

  ${
    2vwomlem.1 $e |- ( a ->2 b ) = 1 $.
    2vwomlem.2 $e |- ( b ->2 a ) = 1 $.
    $( Lemma from 2-variable WOML rule. $)
    2vwomlem   $p |- ( a == b ) = 1 $=
      ( tb wa wn wo wt dfb wf df-f anor2 ax-r1 wi2 anor3 ancom ax-r2 lor df-i2
      3tr ax-r4 a5c ran anass oran3 oran 2an lan 3tr2 or0 le1 2vwomr2 lea leo
      ler2an lelor bltr lebi ax-wom ) ABEABFZAGZBGZFZHZIABJVEKHVEVBVEGZFZHVEIKV
      GVEKIGZVGLAABHZGZHZGZVBVIFZVHVGVMVLAVIMNVKIVKAVCVBFZHZBAOZIVJVNAVJVDVNVDV
      JABPNVBVCQRSVPVOBATNDUAUBVMVBVBVCHZFZVIFVBVQVIFZFVGVBVRVIVRVBVBVCUCNUDVBV
      QVIUEVSVFVBVSVAGZVDGZFVFVQVTVIWAABUFABUGUHVAVDPRUIUAUJRSVEUKAVEVBAVEFZHZI
      WCULIVBVAHZWCWDIABBVDHZABOZIWFWEABTNCRUMNVAWBVBVAAVEABUNVAVDUOUPUQURUSUTU
      JR $.
      $( [13-Nov-98] $)
  $}

  ${
    wr5-2v.1 $e |- ( a == b ) = 1 $.
    $( WOML derived from 2-variable axioms. $)
    wr5-2v $p |- ( ( a v c ) == ( b v c ) ) = 1 $=
      ( wo wi2 wn wa wt df-i2 ax-r1 anandir anass anor3 lan ax-r2 2an 3tr2 lor
      wi1 df-i1 tb wlem1 skr0 lea bltr le1 lebi leo lelan lelor 2vwomr1a lear
      2vwomlem ) ACEZBCEZUOUPFUPUOGZUPGZHZEZIUOUPJUPAGZURHZEZAUPFZUTIVDVCAUPJKV
      BUSUPVABGZHCGZHZVAVFHZVEVFHZHVBUSVAVEVFLVGVAVIHVBVAVEVFMVIURVABCNZOPVHUQV
      IURACNZVJQRSAUPAUPTVAAUPHZEZIAUPUAIVMIVMIVAABHZEZVMIABTZVOIVPIVPBATZHZVPV
      RIABUBVRDABUCUDKZVPVQUEUFVPUGUHABUAPVNVLVABUPABCUIUJUKUFVMUGUHKPULRPUPUOF
      UOURUQHZEZIUPUOJUOVEUQHZEZBUOFZWAIWDWCBUOJKWBVTUOVEVAHVFHZVIVHHWBVTVEVAVF
      LWEVEVHHWBVEVAVFMVHUQVEVKOPVIURVHUQVJVKQRSBUOBUOTVEBUOHZEZIBUOUAIWGIWGIVE
      BAHZEZWGIVQWIIVQIVRVQVSVPVQUMUFVQUGUHBAUAPWHWFVEAUOBACUIUJUKUFWGUGUHKPULR
      PUN $.
      $( [11-Nov-98] $)
  $}

$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Weak orthomodular lattices
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  ${
    wom3.1 $e |- ( a == b ) = 1 $.
    $( Weak orthomodular law for study of weakly orthomodular lattices. $)
    wom3 $p |- a =< ( ( a v c ) == ( b v c ) ) $=
      ( wt wo tb le1 wr5-2v ax-r1 bile letr ) AEACFBCFGZAHEMMEABCDIJKL $.
      $( [13-Nov-98] $)
  $}

  ${
    wlor.1 $e |- ( a == b ) = 1 $.
    $( Weak orthomodular law. $)
    wlor $p |- ( ( c v a ) == ( c v b ) ) = 1 $=
      ( wo tb wt ax-a2 2bi wr5-2v ax-r2 ) CAEZCBEZFACEZBCEZFGLNMOCAHCBHIABCDJK
      $.
      $( [24-Sep-97] $)
  $}

  ${
    wran.1 $e |- ( a == b ) = 1 $.
    $( Weak orthomodular law. $)
    wran $p |- ( ( a ^ c ) == ( b ^ c ) ) = 1 $=
      ( wa tb wn wo wt df-a 2bi wr4 wr5-2v ax-r2 ) ACEZBCEZFAGZCGZHZGZBGZRHZGZF
      IOTPUCACJBCJKSUBQUARABDLMLN $.
      $( [24-Sep-97] $)
  $}

  ${
    wlan.1 $e |- ( a == b ) = 1 $.
    $( Weak orthomodular law. $)
    wlan $p |- ( ( c ^ a ) == ( c ^ b ) ) = 1 $=
      ( wa tb wt ancom 2bi wran ax-r2 ) CAEZCBEZFACEZBCEZFGLNMOCAHCBHIABCDJK $.
      $( [24-Sep-97] $)
  $}

  ${
    wr2.1 $e |- ( a == b ) = 1 $.
    wr2.2 $e |- ( b == c ) = 1 $.
    $( Inference rule of AUQL. $)
    wr2 $p |- ( a == c ) = 1 $=
      ( tb wa wn wo wt dfb rbi wr1 wran wr5-2v ax-r2 wwbmp wr4 wlor wwbmpr ) AC
      FZACGZBHZCHZGZIZBCFZUFEUGUFFBCGZUEIZUFFJUGUIUFBCKLUHUBUEBACABDMNOPQUAUFFU
      BAHZUDGZIZUFFJUAULUFACKLUKUEUBUJUCUDABDRNSPT $.
      $( [24-Sep-97] $)
  $}

  ${
    w2or.1 $e |- ( a == b ) = 1 $.
    w2or.2 $e |- ( c == d ) = 1 $.
    $( Join both sides with disjunction. $)
    w2or $p |- ( ( a v c ) == ( b v d ) ) = 1 $=
      ( wo wlor wr5-2v wr2 ) ACGADGBDGCDAFHABDEIJ $.
      $( [13-Oct-97] $)
  $}

  ${
    w2an.1 $e |- ( a == b ) = 1 $.
    w2an.2 $e |- ( c == d ) = 1 $.
    $( Join both sides with conjunction. $)
    w2an $p |- ( ( a ^ c ) == ( b ^ d ) ) = 1 $=
      ( wa wlan wran wr2 ) ACGADGBDGCDAFHABDEIJ $.
      $( [13-Oct-97] $)
  $}

  ${
    w3tr1.1 $e |- ( a == b ) = 1 $.
    w3tr1.2 $e |- ( c == a ) = 1 $.
    w3tr1.3 $e |- ( d == b ) = 1 $.
    $( Transitive inference useful for introducing definitions. $)
    w3tr1 $p |- ( c == d ) = 1 $=
      ( wr1 wr2 ) CADFABDEDBGHII $.
      $( [13-Oct-97] $)
  $}

  ${
    w3tr2.1 $e |- ( a == b ) = 1 $.
    w3tr2.2 $e |- ( a == c ) = 1 $.
    w3tr2.3 $e |- ( b == d ) = 1 $.
    $( Transitive inference useful for eliminating definitions. $)
    w3tr2 $p |- ( c == d ) = 1 $=
      ( wr1 w3tr1 ) ABCDEACFHBDGHI $.
      $( [13-Oct-97] $)
  $}



$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Relationship analogues (ordering; commutation) in WOML
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  ${
    wleoa.1 $e |- ( ( a v c ) == b ) = 1 $.
    $( Relation between two methods of expressing "less than or equal to". $)
    wleoa   $p |- ( ( a ^ b ) == a ) = 1 $=
      ( wa wo wr1 wlan wa5c wr2 ) ABEAACFZEABKAKBDGHACIJ $.
      $( [27-Sep-97] $)
  $}

  ${
    wleao.1 $e |- ( ( c ^ b ) == a ) = 1 $.
    $( Relation between two methods of expressing "less than or equal to". $)
    wleao   $p |- ( ( a v b ) == b ) = 1 $=
      ( wo wa wa2 wr1 wancom wr2 wlor wa5b ) ABEZBBCFZEZBMBAEOABGANBACBFZNPADHN
      PBCIHJKJBCLJ $.
      $( [27-Sep-97] $)
  $}

  ${
    wdf-le1.1 $e |- ( ( a v b ) == b ) = 1 $.
    $( Define 'less than or equal to' analogue for ` == ` analogue of ` = ` . $)
    wdf-le1 $p |- ( a =<2 b ) = 1 $=
      ( wle2 wo tb wt df-le ax-r2 ) ABDABEBFGABHCI $.
      $( [27-Sep-97] $)
  $}

  ${
    wdf-le2.1 $e |- ( a =<2 b ) = 1 $.
    $( Define 'less than or equal to' analogue for ` == ` analogue of ` = ` . $)
    wdf-le2 $p |- ( ( a v b ) == b ) = 1 $=
      ( wo tb wle2 wt df-le ax-r1 ax-r2 ) ABDBEZABFZGLKABHICJ $.
      $( [27-Sep-97] $)
  $}

  ${
    wom4.1 $e |- ( a =<2 b ) = 1 $.
    $( Orthomodular law.  Kalmbach 83 p. 22. $)
    wom4 $p |- ( ( a v ( a ' ^ b ) ) == b ) = 1 $=
      ( wn wo wa woml wdf-le2 wlan wlor w3tr2 ) AADZABEZFZEMALBFZEBABGNOAMBLABC
      HZIJPK $.
      $( [13-Oct-97] $)
  $}

  ${
    wom5.1 $e |- ( a =<2 b ) = 1 $.
    wom5.2 $e |- ( ( b ^ a ' ) == 0 ) = 1 $.
    $( Orthomodular law.  Kalmbach 83 p. 22. $)
    wom5 $p |- ( a == b ) = 1 $=
      ( wf wo wn wa wr1 ancom bi1 wr2 wlor or0 wom4 w3tr2 ) AEFZAAGZBHZFABESAEB
      RHZSTEDITSBRJKLMQAANKABCOP $.
      $( [13-Oct-97] $)
  $}

  ${
    wcomlem.1 $e |- ( a == ( ( a ^ b ) v ( a ^ b ' ) ) ) = 1 $.
    $( Analogue of commutation is symmetric.  Similar to Kalmbach 83 p. 22. $)
    wcomlem   $p |- ( b == ( ( b ^ a ) v ( b ^ a ' ) ) ) = 1 $=
      ( wa wn wo ax-a2 bi1 wran ancom wr2 a5c wlan df-a anor1 w2or wr4 wr1
      anass wcon2 w3tr1 wlor a5b wdf-le1 wom4 w3tr2 ) ABDZUGEZBDZFZUGAEZBDZFZBB
      ADZBUKDZFUMUJULUIUGUKBEZFZUKBFZBDZDZUQBDULUIUSBUQUSBBUKFZDZBUSVABDZVBURVA
      BURVAUKBGHIVCVBVABJHKVBBBUKLHKMULUQURDZBDZUTUKVDBUKUQEZUREZFZEZVDAVHAUGAU
      PDZFVHCUGVFVJVGUGVFABNHZVJVGABOHPKQVDVIVDVIUQURNHRKIVEUTUQURBSHKUHUQBUGUQ
      VKTIUAUBRUGBUGBUGBFZBUGFZBVLVMUGBGHVMBUNFZBUGUNBUGUNABJHZUBVNBBAUCHKKUDUE
      UGUNULUOVOULUOUKBJHPUF $.
      $( [27-Jan-02] $)
  $}

  ${
    wdf-c1.1 $e |- ( a == ( ( a ^ b ) v ( a ^ b ' ) ) ) = 1 $.
    $( Show that commutator is a 'commutes' analogue for ` == ` analogue
       of ` = ` . $)
    wdf-c1 $p |- C ( a , b ) = 1 $=
      ( wcmtr wa wn wo wt cmtrcom df-cmtr df-t bi1 wcomlem ax-a1 lan ax-r5
      ax-a2 ax-r2 wr2 w2or wr3 3tr ) ABDBADBAEBAFZEGZBFZAEUEUCEGZGZHABIBAJUGHBU
      EGZUGHUHBKLBUDUEUFABCMAUEAABEZAUEEZGZUJAUEFZEZGZCUKUNUKUMUJGUNUIUMUJBULAB
      NOPUMUJQRLSMTSUAUB $.
      $( [27-Jan-02] $)
  $}

  ${
    wdf-c2.1 $e |- C ( a , b ) = 1 $.
    $( Show that commutator is a 'commutes' analogue for ` == ` analogue
       of ` = ` . $)
    wdf-c2 $p |- ( a == ( ( a ^ b ) v ( a ^ b ' ) ) ) = 1 $=
      ( wa wn wo tb wt le1 lea lel2or lelor wcmtr ax-r1 df-cmtr ax-r2 dfb
      ancom df2le2 anandi oran3 oran2 2an anor3 lan a5c anidm 3tr2 2or le3tr1
      lebi ) AABDZABEZDZFZGZHUPIUOAEZBDZUQUMDZFZFZUOUQFZHUPUTUQUOURUQUSUQBJUQUM
      JKLHABMZVAVCHCNABOPUPAUODZUQUOEZDZFVBAUOQVDUOVFUQVDUOADUOAUORUOAULAUNABJA
      UMJKSPUQUQUMFZUQBFZDZDUQVGDZUQVHDZDZVFUQUQVGVHTVIVEUQVIULEZUNEZDVEVGVMVHV
      NABUAABUBUCULUNUDPUEVLUQUQDUQVJUQVKUQUQUMUFUQBUFUCUQUGPUHUIPUJUK $.
      $( [27-Jan-02] $)
  $}

  ${
    wdf2le1.1 $e |- ( ( a ^ b ) == a ) = 1 $.
    $( Alternate definition of 'less than or equal to'. $)
    wdf2le1 $p |- ( a =<2 b ) = 1 $=
      ( wleao wdf-le1 ) ABABACDE $.
      $( [27-Sep-97] $)
  $}

  ${
    wdf2le2.1 $e |- ( a =<2 b ) = 1 $.
    $( Alternate definition of 'less than or equal to'. $)
    wdf2le2 $p |- ( ( a ^ b ) == a ) = 1 $=
      ( wdf-le2 wleoa ) ABBABCDE $.
      $( [27-Sep-97] $)
  $}

  $( L.e. absorption. $)
  wleo $p |- ( a =<2 ( a v b ) ) = 1 $=
    ( wo wa5c wdf2le1 ) AABCABDE $.
    $( [27-Sep-97] $)

  $( L.e. absorption. $)
  wlea $p |- ( ( a ^ b ) =<2 a ) = 1 $=
    ( wa wo wa2 wa5b wr2 wdf-le1 ) ABCZAIADAIDAIAEABFGH $.
    $( [27-Sep-97] $)

  $( Anything is l.e. 1. $)
  wle1 $p |- ( a =<2 1 ) = 1 $=
    ( wt wo or1 bi1 wdf-le1 ) ABABCBADEF $.
    $( [27-Sep-97] $)

  $( 0 is l.e. anything. $)
  wle0 $p |- ( 0 =<2 a ) = 1 $=
    ( wf wle2 wo tb wt df-le ax-a2 or0 ax-r2 bi1 ) BACBADZAEFBAGLALABDABAHAIJKJ
    $.
    $( [11-Oct-97] $)

  ${
    wle.1 $e |- ( a =<2 b ) = 1 $.
    $( Add disjunct to right of l.e. $)
    wler $p |- ( a =<2 ( b v c ) ) = 1 $=
      ( wo wle2 tb wt df-le ax-a3 ax-r1 rbi ax-r2 wr5-2v ) ABCEZFAOEZOGZHAOIQAB
      EZCEZOGHPSOSPABCJKLRBCRBGZABFZHUATABIKDMNMM $.
      $( [13-Oct-97] $)

    $( Add conjunct to left of l.e. $)
    wlel $p |- ( ( a ^ c ) =<2 b ) = 1 $=
      ( wa an32 bi1 wdf2le2 wran wr2 wdf2le1 ) ACEZBLBEZABEZCEZLMOACBFGNACABDHI
      JK $.
      $( [13-Oct-97] $)

    $( Add disjunct to right of both sides $)
    wleror $p |- ( ( a v c ) =<2 ( b v c ) ) = 1 $=
      ( wo orordir bi1 wr1 wdf-le2 wr5-2v wr2 wdf-le1 ) ACEZBCEZMNEZABEZCEZNQOQ
      OABCFGHPBCABDIJKL $.
      $( [13-Oct-97] $)

    $( Add conjunct to right of both sides $)
    wleran $p |- ( ( a ^ c ) =<2 ( b ^ c ) ) = 1 $=
      ( wa anandir bi1 wr1 wdf2le2 wran wr2 wdf2le1 ) ACEZBCEZMNEZABEZCEZMQOQOA
      BCFGHPACABDIJKL $.
      $( [13-Oct-97] $)

    $( Contrapositive for l.e. $)
    wlecon $p |- ( b ' =<2 a ' ) = 1 $=
      ( wn wa wo ax-a2 bi1 oran wdf-le2 w3tr2 wcon3 wdf2le1 ) BDZADZNOEZBBAFZAB
      FZPDZBQRBAGHQSBAIHABCJKLM $.
      $( [13-Oct-97] $)

  $}

  ${
    wletr.1 $e |- ( a =<2 b ) = 1 $.
    wletr.2 $e |- ( b =<2 c ) = 1 $.
    $( Transitive law for l.e. $)
    wletr   $p |- ( a =<2 c ) = 1 $=
      ( wa wo wdf-le2 wr5-2v wr1 ax-a3 bi1 w3tr2 wlan a5c wr2 wdf2le1 ) ACACFAA
      BCGZGZFZACSARABGZCGZCSUBRUABCABDHIJBCEHUBSABCKLMNTAAROLPQ $.
      $( [13-Oct-97] $)
  $}

  ${
    wbltr.1 $e |- ( a == b ) = 1 $.
    wbltr.2 $e |- ( b =<2 c ) = 1 $.
    $( Transitive inference. $)
    wbltr $p |- ( a =<2 c ) = 1 $=
      ( wo wr5-2v wdf-le2 wr2 wdf-le1 ) ACACFBCFCABCDGBCEHIJ $.
      $( [13-Oct-97] $)
  $}

  ${
    wlbtr.1 $e |- ( a =<2 b ) = 1 $.
    wlbtr.2 $e |- ( b == c ) = 1 $.
    $( Transitive inference. $)
    wlbtr $p |- ( a =<2 c ) = 1 $=
      ( wa wr1 wlan wdf2le2 wr2 wdf2le1 ) ACACFABFACBABCEGHABDIJK $.
      $( [13-Oct-97] $)
  $}

  ${
    wle3tr1.1 $e |- ( a =<2 b ) = 1 $.
    wle3tr1.2 $e |- ( c == a ) = 1 $.
    wle3tr1.3 $e |- ( d == b ) = 1 $.
    $( Transitive inference useful for introducing definitions. $)
    wle3tr1 $p |- ( c =<2 d ) = 1 $=
      ( wbltr wr1 wlbtr ) CBDCABFEHDBGIJ $.
      $( [13-Oct-97] $)
  $}

  ${
    wle3tr2.1 $e |- ( a =<2 b ) = 1 $.
    wle3tr2.2 $e |- ( a == c ) = 1 $.
    wle3tr2.3 $e |- ( b == d ) = 1 $.
    $( Transitive inference useful for eliminating definitions. $)
    wle3tr2 $p |- ( c =<2 d ) = 1 $=
      ( wr1 wle3tr1 ) ABCDEACFHBDGHI $.
      $( [13-Oct-97] $)
  $}

  ${
    wbile.1 $e |- ( a == b ) = 1 $.
    $( Biconditional to l.e. $)
    wbile   $p |- ( a =<2 b ) = 1 $=
      ( wo wr5-2v oridm bi1 wr2 wdf-le1 ) ABABDBBDZBABBCEJBBFGHI $.
      $( [13-Oct-97] $)
  $}

  ${
    wlebi.1 $e |- ( a =<2 b ) = 1 $.
    wlebi.2 $e |- ( b =<2 a ) = 1 $.
    $( L.e. to biconditional. $)
    wlebi   $p |- ( a == b ) = 1 $=
      ( wo wdf-le2 wr1 ax-a2 bi1 wr2 ) AABEZBABAEZKLABADFGLKBAHIJABCFJ $.
      $( [13-Oct-97] $)
  $}

  ${
    wle2.1 $e |- ( a =<2 b ) = 1 $.
    wle2.2 $e |- ( c =<2 d ) = 1 $.
    $( Disjunction of 2 l.e.'s $)
    wle2or $p |- ( ( a v c ) =<2 ( b v d ) ) = 1 $=
      ( wo wleror ax-a2 bi1 wle3tr1 wletr ) ACGBCGZBDGZABCEHCBGZDBGZMNCDBFHMOBC
      IJNPBDIJKL $.
      $( [13-Oct-97] $)

    $( Conjunction of 2 l.e.'s $)
    wle2an $p |- ( ( a ^ c ) =<2 ( b ^ d ) ) = 1 $=
      ( wa wleran ancom bi1 wle3tr1 wletr ) ACGBCGZBDGZABCEHCBGZDBGZMNCDBFHMOBC
      IJNPBDIJKL $.
      $( [13-Oct-97] $)
  $}

  $( Half of distributive law. $)
  wledi $p |- ( ( ( a ^ b ) v ( a ^ c ) ) =<2
        ( a ^ ( b v c ) ) ) = 1 $=
    ( wa wo anidm bi1 wr1 wlea wle2or oridm wlbtr ancom wbltr wle2an ) ABDZACDZ
    EZRRDZABCEZDSRSRRFGHRARTRAAEZAPAQAABIACIJUAAAKGLPBQCPBADZBPUBABMGBAINQCADZC
    QUCACMGCAINJON $.
    $( [13-Oct-97] $)

  $( Half of distributive law. $)
  wledio $p |- ( ( a v ( b ^ c ) ) =<2
       ( ( a v b ) ^ ( a v c ) ) ) = 1 $=
    ( wa wo anidm bi1 wr1 wleo wle2an wbltr ax-a2 wlbtr wle2or oridm ) ABCDZEAB
    EZACEZDZSEZSASPSAAADZSUAAUAAAFGHAQARABIACIJKBQCRBBAEZQBAIUBQBALGMCCAEZRCAIU
    CRCALGMJNTSSOGM $.
    $( [13-Oct-97] $)

  $( Commutation with 0.  Kalmbach 83 p. 20. $)
  wcom0 $p |- C ( a , 0 ) = 1 $=
    ( wf wa wn wo comm0 df-c2 bi1 wdf-c1 ) ABAABCABDCEABAFGHI $.
    $( [13-Oct-97] $)

  $( Commutation with 1.  Kalmbach 83 p. 20. $)
  wcom1 $p |- C ( 1 , a ) = 1 $=
    ( wt wa wn wo comm1 df-c2 bi1 wdf-c1 ) BABBACBADCEBAAFGHI $.
    $( [13-Oct-97] $)

  ${
    wlecom.1 $e |- ( a =<2 b ) = 1 $.
    $( Comparable elements commute.  Beran 84 2.3(iii) p. 40. $)
    wlecom $p |- C ( a , b ) = 1 $=
      ( wn wa wo a5b bi1 wr1 wdf2le2 wr5-2v wr2 wdf-c1 ) ABAAABDZEZFZABEZOFPAPA
      ANGHIAQOQAABCJIKLM $.
      $( [13-Oct-97] $)
  $}

  ${
    wbctr.1 $e |- ( a == b ) = 1 $.
    wbctr.2 $e |- C ( b , c ) = 1 $.
    $( Transitive inference. $)
    wbctr $p |- C ( a , c ) = 1 $=
      ( wa wn wo wdf-c2 wran w2or w3tr1 wdf-c1 ) ACBBCFZBCGZFZHAACFZAOFZHBCEIDQ
      NRPABCDJABODJKLM $.
      $( [13-Oct-97] $)
      $( [13-Oct-97] $)
  $}

  ${
    wcbtr.1 $e |- C ( a , b ) = 1 $.
    wcbtr.2 $e |- ( b == c ) = 1 $.
    $( Transitive inference. $)
    wcbtr $p |- C ( a , c ) = 1 $=
      ( wa wn wo wdf-c2 wlan wr4 w2or wr2 wdf-c1 ) ACAABFZABGZFZHACFZACGZFZHABD
      IORQTBCAEJPSABCEKJLMN $.
      $( [13-Oct-97] $)
  $}

  $( Weak commutation law. $)
  wcomorr $p |- C ( a , ( a v b ) ) = 1 $=
    ( wo wleo wlecom ) AABCABDE $.
    $( [13-Oct-97] $)

  $( Weak commutation law. $)
  wcoman1 $p |- C ( ( a ^ b ) , a ) = 1 $=
    ( wa wlea wlecom ) ABCAABDE $.
    $( [13-Oct-97] $)

  ${
    wcomcom.1 $e |- C ( a , b ) = 1 $.
    $( Commutation is symmetric.  Kalmbach 83 p. 22. $)
    wcomcom   $p |- C ( b , a ) = 1 $=
      ( wcmtr wt cmtrcom ax-r2 ) BADABDEBAFCG $.
      $( [13-Oct-97] $)

    $( Commutation equivalence.  Kalmbach 83 p. 23. $)
    wcomcom2 $p |- C ( a , b ' ) = 1 $=
      ( wn wa wo wdf-c2 ax-a1 bi1 wlan wr5-2v wr2 ax-a2 wdf-c1 ) ABDZAAODZEZAOE
      ZFZRQFZAABEZRFSABCGUAQRBPABPBHIJKLSTQRMILN $.
      $( [13-Oct-97] $)

    $( Commutation equivalence.  Kalmbach 83 p. 23. $)
    wcomcom3 $p |- C ( a ' , b ) = 1 $=
      ( wn wcomcom wcomcom2 ) BADBAABCEFE $.
      $( [13-Oct-97] $)

    $( Commutation equivalence.  Kalmbach 83 p. 23. $)
    wcomcom4 $p |- C ( a ' , b ' ) = 1 $=
      ( wn wcomcom3 wcomcom2 ) ADBABCEF $.
      $( [13-Oct-97] $)

    $( Commutation dual.  Kalmbach 83 p. 23. $)
    wcomd $p |- ( a == ( ( a v b ) ^ ( a v b ' ) ) ) = 1 $=
      ( wn wa wo wcomcom4 wdf-c2 wcon3 oran bi1 wcon2 w2an wr1 wr2 ) AADZBDZEZP
      QDEZFZDZABFZAQFZEZATPQABCGHIUARDZSDZEZUDTUGTUGDRSJKLUDUGUBUEUCUFUBUEABJKU
      CUFAQJKMNOO $.
      $( [13-Oct-97] $)

    $( Lemma 3(ii) of Kalmbach 83 p. 23. $)
    wcom3ii $p |- ( ( a ^ ( a ' v b ) ) == ( a ^ b ) ) = 1 $=
      ( wa wn wo wcomcom wcomd wlan anass bi1 wr1 ax-a2 a5c wr2 w2an ) ABDZAAEZ
      BFZDZQABAFZBRFZDZDZTBUCABAABCGHIUDAUADZUBDZTUFUDUFUDAUAUBJKLUEAUBSUEAABFZ
      DZAUAUGAUAUGBAMKIUHAABNKOUBSBRMKPOOL $.
      $( [13-Oct-97] $)
  $}

  ${
    wcomcom5.1 $e |- C ( a ' , b ' ) = 1 $.
    $( Commutation equivalence.  Kalmbach 83 p. 23. $)
    wcomcom5 $p |- C ( a , b ) = 1 $=
      ( wn wa wo wcomcom4 wdf-c2 ax-a1 bi1 w2an w2or w3tr1 wdf-c1 ) ABADZDZPBDZ
      DZEZPRDZEZFAABEZAQEZFPROQCGHAPAIJZUBSUCUAAPBRUDBRBIJKAPQTUDQTQIJKLMN $.
      $( [13-Oct-97] $)
  $}

  ${
    wcomdr.1 $e |- ( a == ( ( a v b ) ^ ( a v b ' ) ) ) = 1 $.
    $( Commutation dual.  Kalmbach 83 p. 23. $)
    wcomdr $p |- C ( a , b ) = 1 $=
      ( wn wa wo df-a bi1 oran wcon2 w2or wr4 wr2 wdf-c1 wcomcom5 ) ABADZBDZAPQ
      EZPQDEZFZAABFZAQFZEZTDZCUCUADZUBDZFZDZUDUCUHUAUBGHUGTUERUFSUARUARDABIHJUB
      SUBSDAQIHJKLMMJNO $.
      $( [13-Oct-97] $)
  $}

  ${
    wcom3i.1 $e |- ( ( a ^ ( a ' v b ) ) == ( a ^ b ) ) = 1 $.
    $( Lemma 3(i) of Kalmbach 83 p. 23. $)
    wcom3i $p |- C ( a , b ) = 1 $=
      ( wn wa wo anor1 bi1 wcon2 wran ancom wr2 wlor wlea wom4 ax-a2 w3tr2
      wdf-c1 ) ABABDZEZTDZAEZFTABEZFZAUCTFZUBUCTUBAADBFZEZUCUBUFAEZUGUAUFATUFTU
      FDABGHIJUHUGUFAKHLCLMTAASNOUDUETUCPHQR $.
      $( [13-Oct-97] $)
  $}

  ${
    wfh.1 $e |- C ( a , b ) = 1 $.
    wfh.2 $e |- C ( a , c ) = 1 $.
    $( Weak structural analog of Foulis-Holland Theorem. $)
    wfh1 $p |- ( ( a ^ ( b v c ) ) ==
               ( ( a ^ b ) v ( a ^ c ) ) ) = 1 $=
      ( wa wo wledi wn wf ancom bi1 df-a w2or wr1 wcon3 wr2 wcon2 w2an anass
      wcomcom2 wcom3ii anandi w3tr1 wlan an12 oran dff an0 wom5 ) ABFZACFZGZABC
      GZFZUMUOABCHUOUMIZFZAUNBIZCIZFZFZFZJUQUNAFZAIZURGZVDUSGZFZFZVBUOVCUPVGUOV
      CAUNKLUMVGUMVEIZVFIZGZVGIUKVIULVJUKVIABMLULVJACMLNVKVGVGVKIZVGVLVEVFMLOPQ
      RSVHUNAUTFZFZVBVHUNAVGFZFZVNVHVPUNAVGTLVOVMUNAVEFZAVFFZFZAURFZAUSFZFZVOVM
      VQVTVRWAAURABDUAUBAUSACEUAUBSVOVSAVEVFUCLVMWBAURUSUCLUDUEQVNVBUNAUTUFLQQV
      BAJFZJVAJAVAUNUNIZFZJUTWDUNUTUNUNUTIZUNWFBCUGLOPUEJWEJWEUNUHLOQUEWCJAUILQ
      QUJO $.
      $( [13-Oct-97] $)

    $( Weak structural analog of Foulis-Holland Theorem. $)
    wfh2 $p |- ( ( b ^ ( a v c ) ) ==
               ( ( b ^ a ) v ( b ^ c ) ) ) = 1 $=
      ( wa wo wledi wn wf oran bi1 df-a wcon2 wran wr4 wr2 wlan an4 wcomcom
      wcomcom2 wcom3ii ancom ax-a1 wr5-2v wcomcom3 anass wr1 an12 dff w3tr1
      an0 wom5 ) BAFZBCFZGZBACGZFZUPURBACHURUPIZFZAIZCBUOIZFZFZFZJUTVACFZVCFZVE
      UTVAUQFZVCFZVGUTVABFZUQVBFZFZVIUTURBIVAGZVBFZFZVLUSVNURUPVNUPUNIZVBFZIZVN
      IUPVRUNUOKLVQVNVPVMVBUNVMUNVMIBAMLNOPQNRVOBVMFZVKFZVLVOVTBUQVMVBSLVSVJVKV
      SBVAFZVJBVABAABDTUAUBWAVJBVAUCLQOQQVLVIVABUQVBSLQVHVFVCVHVAVAIZCGZFVFUQWC
      VAAWBCAWBAUDLUERVACACEUFUBQOQVGVEVACVCUGLQVEVAJFZJVDJVABCVBFFZUOVBFZVDJWF
      WEWFWEBCVBUGLUHVDWECBVBUILJWFUOUJLUKRWDJVAULLQQUMUH $.
      $( [13-Oct-97] $)

    $( Weak structural analog of Foulis-Holland Theorem. $)
    wfh3 $p |- ( ( a v ( b ^ c ) ) ==
               ( ( a v b ) ^ ( a v c ) ) ) = 1 $=
      ( wa wo wn wcomcom4 wfh1 anor2 bi1 df-a wr1 wlor wr4 wr2 oran w2an w3tr2
      wcon1 ) ABCFZGZABGZACGZFZAHZBHZCHZGZFZUGUHFZUGUIFZGZUCHZUFHZUGUHUIABDIACE
      IJUKAUJHZGZHZUOUKUSAUJKLURUCUQUBAUBUQUBUQBCMLNOPQUNULHZUMHZFZHZUPUNVCULUM
      RLVBUFUFVBUDUTUEVAUDUTABRLUEVAACRLSNPQTUA $.
      $( [13-Oct-97] $)

    $( Weak structural analog of Foulis-Holland Theorem. $)
    wfh4 $p |- ( ( b v ( a ^ c ) ) ==
               ( ( b v a ) ^ ( b v c ) ) ) = 1 $=
      ( wa wo wn wcomcom4 wfh2 anor2 bi1 df-a wr1 wlor wr4 wr2 oran w2an w3tr2
      wcon1 ) BACFZGZBAGZBCGZFZBHZAHZCHZGZFZUGUHFZUGUIFZGZUCHZUFHZUHUGUIABDIACE
      IJUKBUJHZGZHZUOUKUSBUJKLURUCUQUBBUBUQUBUQACMLNOPQUNULHZUMHZFZHZUPUNVCULUM
      RLVBUFUFVBUDUTUEVAUDUTBARLUEVABCRLSNPQTUA $.
      $( [13-Oct-97] $)

    $( Th. 4.2 Beran p. 49. $)
    wcom2or $p |- C ( a , ( b v c ) ) = 1 $=
      ( wo wa wn wcomcom wdf-c2 ancom 2or bi1 wr2 w2or or4 wfh1 wcomcom3 wr1
      wdf-c1 ) BCFZAUAAUAABGZACGZFZAHZBGZUECGZFZFZUAAGZUAUEGZFZUAUBUFFZUCUGFZFZ
      UIBUMCUNBBAGZBUEGZFZUMBAABDIJURUMUPUBUQUFBAKBUEKLMNCCAGZCUEGZFZUNCAACEIJV
      AUNUSUCUTUGCAKCUEKLMNOUOUIUBUFUCUGPMNULUIUJUDUKUHUJAUAGZUDUJVBUAAKMABCDEQ
      NUKUEUAGZUHUKVCUAUEKMUEBCABDRACERQNOSNTI $.
      $( [10-Nov-98] $)

    $( Th. 4.2 Beran p. 49. $)
    wcom2an $p |- C ( a , ( b ^ c ) ) = 1 $=
      ( wa wn wo wcomcom4 wcom2or df-a con2 ax-r1 bi1 wcbtr wcomcom5 ) ABCFZAGZ
      BGZCGZHZQGZRSTABDIACEIJUAUBUBUAQUABCKLMNOP $.
      $( [10-Nov-98] $)

  $}

  $( Negated biconditional (distributive form) $)
  wnbdi $p |- ( ( a == b ) ' ==
             ( ( ( a v b ) ^ a ' ) v ( ( a v b ) ^ b ' ) ) ) = 1 $=
    ( tb wn wo wa dfnb bi1 wcomorr wcomcom wcomcom2 ax-a2 wcbtr wfh1 wr2 ) ABCD
    ZABEZADZBDZEFZQRFQSFEPTABGHQRSQAAQABIJKQBBQBBAEZQBAIUAQBALHMJKNO $.
    $( [13-Oct-97] $)

  $( Lemma for KA14 soundness. $)
  wlem14 $p |- ( ( ( a ^ b ' ) v a ' ) ' v
            ( ( a ^ b ' ) v ( ( a ' ^ ( ( a v b ' ) ^ ( a v b ) ) )
               v ( a ' ^ ( ( a v b ' ) ^ ( a v b ) ) ' ) ) ) ) = 1 $=
    ( wn wa wo wt df-t ax-r1 ax-a2 bi1 wwbmpr wlan anidm wr1 wleo wle2an wbltr
    wlecom wcomcom3 wcomcom4 wfh1 an1 w3tr2 wlor ) ABCZDZACZEZCZUFUGAUEEZABEZDZ
    DUGULCZDEZEZEUIUHEZUPUHUIEZFUQUHGHUPUQUIUHIJKUOUHUIUNUGUFUGULUMEZDUGFDZUNUG
    URFUGURFFURULGHJLUGULUMAULAULAAADZULUTAUTAAMJNAUJAUKAUEOABOPQRZSAULVATUAUSU
    GUGUBJUCUDUDK $.
    $( [25-Oct-97] $)

  ${
    wr5.1 $e |- ( a == b ) = 1 $.
    $( Proof of weak orthomodular law from weaker-looking equivalent,
       ~wom3 , which in turn is derived from ~ax-wom . $)
    wr5 $p |- ( ( a v c ) == ( b v c ) ) = 1 $=
      ( wr5-2v ) ABCDE $.
      $( [25-Oct-97] $)
  $}


$(
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        Kalmbach axioms (soundness proofs) that require WOML
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
$)

  $( >>>Remove "id" when bug is fixed. $)
  $( Soundness theorem for Kalmbach's quantum propositional logic axiom KA2. $)
  ska2 $p |- ( ( a == b ) ' v ( ( b == c ) ' v ( a == c ) ) ) = 1 $=
    ( tb wn wo wa wt dfnb dfb 2or ax-a3 ax-r1 id le1 ax-a2 or12 orordi lor
    ax-r2 df-t oran3 leor le2or lelor bltr letr lebi wcomorr bi1 wcbtr wcomcom
    wcomcom2 wfh4 or1 ran ancom an1 wr2 or32 w2or wlor wwbmpr orordir anor3
    wcom2or oran leo wr5-2v wcomcom3 wfh1 wwbmp ax-r5 ledi leror ) ABDEZBCDEZAC
    DZFZFABFZAEZBEZFGZBCFZWBCEZFZGZACGZWAWEGZFZFZFZHVPWCVSWKABIVQWGVRWJBCIACJKK
    WLWCWGFZWJFZHWNWLWCWGWJLMWNWNHWNNWNHWNOHVTWAGZWBVTGZFZWBWDGZWDWEGZFZFZWJFZW
    NHWOWPWRFZWSFZFZWJFZXBXFHWOWBVTWDFZGZWSFZFZWJFZXFXKWJXJFZHXJWJPXLWOWJXIFZFZ
    HWJWOXIQXNWOWHWIWBFZWSFZFZFZXRWHWOXPFZFZHWOWHXPQXTWHWIWBWOFZWBWSFZFZFZFZHXS
    YDWHXSXOWOWSFZFZYDWOXOWSQYGWIWBYFFZFYDWIWBYFLYHYCWIWBWOWSRSTTSYEWHWIWBWAFZW
    FFZFZFZYLWIWHYJFZFZHWHWIYJQYNHYNOHYMYNHWHWAWEFZFZYMHWHWHEZFZYPWHUAYPYRYOYQW
    HACUBSMTYOYJWHWAYIWEWFWAWBUCWEWBUCUDUEUFYMWIUCUGUHTYDYKWHYCYJWIYAYIYBWFYAWB
    VTFZYIGZYIVTWBWAVTBBVTBBAFZVTBAUIUVAVTBAPUJUKZULUMVTAAVTABUIULUMUNYTYIYTHYI
    GZYIYSHYIYSAWBBFZFZHWBABQUVEAHFHUVDHAUVDBWBFZHWBBPHUVFBUAMZTSAUOTTUPUVCYIHG
    YIHYIUQYIURTTUJUSYBWBWDFZWFGZWFWDWBWEWDBBWDBCUIZULUMWDCCWDCCBFZWDCBUIUVKWDC
    BPZUJUKULUMUNUVIWFUVIHWFGZWFUVHHWFUVHWDWBFZHWBWDPUVNUVFCFZHBCWBUTUVOCUVFFZH
    UVFCPUVPCHFHUVFHCUVGSCUOTTTTUPUVMWFHGWFHWFUQWFURTTUJUSVAVBVBVCTTXMXQWOXMWHW
    IXIFZFZXQXMUVRWHWIXILUJUVQXPWHUVQWIXHFZWSFZXPUVQUVTUVTUVQWIXHWSLMUJUVSXOWSU
    VSWIXGWBGZFZXOUVSUWBXHUWAWIWBXGUQSUJUWBWIXGFZXOGZXOXGWIWBXGACFZEZWIXGUWEUWE
    XGUWEUWEBFZXGUWEBUIUWGXGUWGVTUVKFXGACBVDUVKWDVTUVLSTUJUKULUMUWFWIWIUWFACVEM
    UJUKXGBBXGBVTWDUVBUVJVFULUMUNUWDXOUWDHXOGZXOUWCHXOUWCHUWCOHWIUWEFZUWCHWIWIE
    ZFUWIWIUAUWJUWEWIUWEUWJACVGMSTUWEXGWIAVTCWDABVHCBUCUDUEUFUHUPUWHXOHGXOHXOUQ
    XOURTTUJUSUSVIUSVBUSVBVCTTXJXEWJXIXDWOXHXCWSWBVTWDBVTUVBVJBWDUVJVJVKVIVBVIV
    LMXEXAWJXEWQWRFZWSFZXAXEWOXCFZWSFZUWLUWNXEWOXCWSLMUWMUWKWSUWKUWMWOWPWRLMVMT
    WQWRWSLTVMTXAWMWJWQWCWTWGWQWOVTWBGZFWCWPUWOWOWBVTUQSVTWAWBVNUFWTWDWBGZWSFWG
    WRUWPWSWBWDUQVMWDWBWEVNUFUDVOUFUHTTT $.
    $( [10-Nov-98] $)
