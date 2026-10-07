/*****************************************************************************/
/* lattice2g.c - Lattice tester for orthomodular lattice algebras            */
/*                                                                           */
/*       Copyright (C) 2010  NORMAN D. MEGILL  <nm@alum.mit.edu>             */
/*             License terms:  GNU General Public License                    */
/*****************************************************************************/
/*34567890123456 (79-character line to adjust text window width) 678901234567*/

#define VERSION "1.8 17-Apr-2010"
/* 1.8 17-Apr-2010 Added lattice2gperes7 options; node/atom xref for -p */
/* 1.71 24-Apr-2009 Added extended + notation for Greechie diagrams */
/* To debug with version before partial evaluations, undefine PEVAL */
#define PEVAL


#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#if defined(PEVAL)
#include <limits.h>
#else
#endif

/* MAX_NODES must be less than 32767-128=32639 based on the wideChar typedef
   of short.  However, making it smaller e.g. 1000 will reduce memory
   requirement of program due to 2-d MAX_NODES x MAX_NODES arrays. */
#define MAX_NODES 1000
/* MAX_NODENAME is the highest "extended ASCII" (16-bit) code for
   the name of a node, plus 1.  Node names beyond z start at "character"
   128. */
#define MAX_NODENAME MAX_NODES + 128 - 23 * 2
/* Binary infix operator list - i is only for Polish conversion */
/* Note: i is now obsolete - it used to be "universal implication" -
   but it is still implemented in beran.c and beranf.c */
/* 2/20/00 - Added ~ (NOT) & (AND) V (OR) } (implies) : (bicond)
   classical metalogical connectives */
/* 2/24/00 - Added @ (for all) ] (exists) */
#define ALL_BIN_CONNECTIVES "^v#OI2345=<>[&V}:"
/* MAX_BIN_CONNECTIVES is the length of ALL_BIN_CONNECTIVES */
#define MAX_BIN_CONNECTIVES 17
#define LOGIC_BIN_CONNECTIVES "&V}:"
#define LOGIC_AND_RELATION_CONNECTIVES "=<>[&V}:~"
#define OPER_AND_RELATION_BIN_CONNECTIVES "^v#OI2345=<>["
#define QUANTIFIER_CONNECTIVES "@]"
/* Lattice binary operations */
/* (In the future direct references to operation symbols will be
   changed to use these constants) */
#define INF_OPER '^'
#define SUP_OPER 'v'
#define ID_OPER '#'
#define IMP0_OPER 'O'
#define IMP1_OPER 'I'
#define IMP2_OPER '2'
#define IMP3_OPER '3'
#define IMP4_OPER '4'
#define IMP5_OPER '5'
/* Lattice relations */
#define EQ_OPER '='
#define LE_OPER '<'
#define GE_OPER '>'
#define COM_OPER '['
/* Negation prefix operator */
#define NEG_OPER '-'
/* 2/20/00 - Added classical metalogical NOT */
#define NOT_OPER '~'
/* 2/20/00 - Added classical binary metalogical connectives */
#define AND_OPER '&'
#define OR_OPER 'V'
#define IMPL_OPER '}'
#define BI_OPER ':'
/* 2/20/00 - Added classical truth values - these should be different
   from ASCII letters to avoid ambiguity, but less than MAX_NODES to
   avoid operation table overflow, and nonzero to avoid end-of-string
   problems */
#define FALSE_CONST 1
#define TRUE_CONST 2
/* 2/24/00 - Added quantifiers */
#define FORALL_OPER '@'
#define EXISTS_OPER ']'
/* Old "universal implication" - now obsolete */
#define UNIV_IMPL 'i'
/* List of legal variable names - note v,i,o skipped because of operators */
#define VAR_LIST "abcdefghjklmnpqrstuwxyz"
/* MAX_VARS is the length of VAR_LIST */
#define MAX_VARS 23
/* MAX_STACK is length of longest formula expressed in Polish notation */
#define MAX_STACK 10000
/* MAX_STACK2 is the maximum nesting level of a formula */
#define MAX_STACK2 1000
/* Largest number of user hypotheses */
#define MAX_HYPS 50
/* Largest number of lattices */
#define MAX_LATTICES 1000

/* Mapping for Greechie diagram atoms */
#define ATOM_MAP "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs" \
    "tuvwxyz!\"#$%&'()*-/:;<=>?@[\\]^_`{|}~"
/* Maximum number of blocks */
#define MAX_BLOCKS 200
/* Minimum block size - only 3 and 4 are implemented */
#define MIN_BLOCK_SIZE 3
/* Maximum block size - only 3 and 4 are implemented */
#define MAX_BLOCK_SIZE 4

/******************** Start of string handling prototypes ********************/
typedef char* vstring;

typedef short wideChar;
typedef wideChar* wideVstring;
#define WIDE_ENDCHAR 0
wideChar wideNullString[] = {WIDE_ENDCHAR};

/* String assignment - MUST be used to assign vstrings */
void let(vstring *target,vstring source);
void wideLet(wideVstring *target, wideVstring source);
/* String concatenation - last argument MUST be NULL */
vstring cat(vstring string1,...);
wideVstring wideCat(wideVstring string1,...);

/* Emulate BASIC linput statement; returns NULL if EOF */
/* Note that linput assigns target string with let(&target,...) */
  /*
    BASIC:  linput "what";a$
    c:      linput(NULL,"what?",&a);

    BASIC:  linput #1,a$                        (error trap on EOF)
    c:      if (!linput(file1,NULL,&a)) break;  (break on EOF)

  */
vstring linput(FILE *stream, vstring ask, vstring *target);

/* Emulation of BASIC string functions */
vstring seg(vstring sin, long p1, long p2);
vstring mid(vstring sin, long p, long l);
wideVstring wideMid(wideVstring sin, long p, long l);
vstring left(vstring sin, long n);
wideVstring wideLeft(wideVstring sin, long n);
vstring right(vstring sin, long n);
wideVstring wideRight(wideVstring sin, long n);
vstring edit(vstring sin, long control);
vstring space(long n);
vstring string(long n, char c);
wideVstring wideString(long n, wideChar c);
wideVstring wide(vstring s);
vstring chr(long n);
vstring xlate(vstring sin, vstring control);
vstring date(void);
vstring time_(void);
vstring num(double x);
vstring num1(double x);
vstring str(double x);
long len(vstring s);
long wideLen(wideVstring s);
void wideCpy(wideVstring t, wideVstring s);
long instr(long start, vstring sin, vstring s);
long wideChrInStr(long start, wideVstring s, wideChar c);
long ascii_(vstring c);
double val(vstring s);
/* Emulation of PROGRESS string functions added 11/25/98 */
vstring entry(long element, vstring list);
long lookup(vstring expression, vstring list);
long numEntries(vstring list);
long entryPosition(long element, vstring list);
/* Print to log file as well as terminal if fplog opened */
void print2(char* fmt,...);
FILE *fplog = NULL;
/* Opens files with error message; opens output files with
   backup of previous version.   Mode must be "r" or "w". */
FILE *fSafeOpen(vstring fileName, vstring mode);


/******* Special pupose routines for better
      memory allocation (use with caution) *******/
/* Make string have temporary allocation to be released by next let() */
/* Warning:  after makeTempAlloc() is called, the vstring may NOT be
   assigned again with let() */
void makeTempAlloc(vstring s);   /* Make string have temporary allocation to be
                                    released by next let() */
/* Remaining prototypes (outside of mmvstr.h) */
void *tempAlloc(long size);     /* String memory allocation/deallocation */

#define MAX_ALLOC_STACK 100
int tempAllocStackTop=0;        /* Top of stack for tempAlloc functon */
int startTempAllocStack=0;      /* Where to start freeing temporary allocation
                                    when let() is called (normally 0, except in
                                    special nested vstring functions) */
void *tempAllocStack[MAX_ALLOC_STACK];

/* Bug check error */
void bug(int bugNum);

/******************** End of string handling prototypes **********************/

/******************** Prototypes *********************************************/
void usersGreechieDiagrams(void);
void printhelp(void);
void testAllLattices(void);
void findCommutingPairs(void);
void init(void);
void initLattice(long latticeNum);

void greechie3(vstring name, vstring glattice);
wideChar test(void);
vstring unabbreviate(vstring eqn);
wideVstring wideUnabbreviate(wideVstring eqn);
vstring subformulaList(vstring eqn);
vstring toPolish(vstring equation);
long subEqnLen(vstring subEqn);
wideVstring wideFromPolish(wideVstring polishEqn);
vstring fromPolish(vstring polishEqn);
wideChar eval(wideVstring trialEqn, long eqnLen);
wideChar fastEval(wideVstring trialEqn, long startChar);
wideChar ultraFastEval(wideVstring trialEqn, long eqnLen);
#if defined(PEVAL)
void partialEval(wideVstring trialEqn, vstring varFlags, long *eqnLen);
#else
#endif
wideVstring wideSubformula(wideVstring eqn);
vstring subformula(vstring eqn);
long wideSubformulaLen(wideVstring eqn, long startChar);
long subformulaLen(vstring eqn, long startChar);
wideChar lookupCompl(wideChar arg);
wideChar lookupNot(wideChar arg);
wideChar lookupBinOp(wideChar operation, wideChar arg1,
    wideChar arg2);
wideVstring unPrintableString(vstring sin);
vstring printableString(wideVstring sin);
long nodeToAtom(long node);
vstring printableAtomName(long atomNum);

/******************** Global variables ***************************************/
wideVstring nodeList[MAX_NODES];
wideVstring WIDE_LOGIC_BIN_CONNECTIVES = wideNullString;
wideVstring WIDE_ALL_BIN_CONNECTIVES = wideNullString;
                                    /* Converted from LOGIC_BIN_CONNECTIVES */
wideVstring sup[MAX_NODES][MAX_NODES]; /* Supremum (disjunction) table */
wideVstring nodeNames = wideNullString; /* List of node names in nodeList order */
long nodes;
vstring latticeName = ""; /* Name of lattice being worked with */
vstring equation = ""; /* Expression being tested */
vstring hypList[MAX_HYPS]; /* List of user's hypotheses (0 or more) */
vstring polHypList[MAX_HYPS]; /* List of user's hypotheses in Polish */
long hypotheses;
vstring conclusion = ""; /* User's conclusion to test */
vstring polConclusion = ""; /* Concl in Polish, with quantifiers stripped */
vstring quantifiers = ""; /* Quantifiers in prefix of prenex normal form */
vstring quantifierTypes = ""; /* @ or ] in order of occurrence */
vstring quantifierVars = ""; /* Quantified vars in order of occurrence */
vstring failingAssignment = ""; /* Assignment that violated lattice */
long userArg; /* -1 = test all; n = test only nth lattice */
long startArg = 0; /* Lattice # to start from */
long endArg = 0; /* Lattice # to end at */
/* Special for Greechie diagram program latticeg.c */
long ATOM_MAPLen; /* Pre-computed length of ATOM_MAP */
wideVstring lletterlist = wideNullString; /* Node names for atoms */
wideVstring uletterlist = wideNullString; /* Node names for complement atoms */
long glatticeNum;
long glatticeCount;
vstring greechieStmt = ""; /* Greechie lattice C statement */
wideVstring atomReverseMap = wideNullString; /* Map back to input diagram */
char oneLineOutput = 0; /* Set to 1 by -1 option */
char removeLegs = 0; /* Set to 1 by -l option */
FILE *fp = NULL;  /* Input file of greechie diagrams */
char stdInputMode = 0; /* Set to 1 by --i option, then to 2 upon EOF */
long fileLattices = 0; /* Number of input file diagrams */
long fileLineNum = 0; /* Most recent line number (= lattice number) read */

/* The block stuff was made global for use outside of greechie3() */
/* Block information for Greechie diagrams */
long atoms;
long block[MAX_BLOCKS + 1][MAX_BLOCK_SIZE + 1];
long blockSize[MAX_BLOCKS + 1];
long block4Offset[MAX_BLOCKS + 1];
long blocks;

/* lattice2gperes7.c */
long startNode = 0; /* > 0 means test starting at this node (1 through n) */
long spanNodes = 0; /* > 0 means test this many nodes */
long secondStartNode = 0; /* > 0 means start 2nd inner loop at this node */
long secondSpanNodes = 0; /* > 0 means test this many 2nd inner loop nodes */
/* end of lattice2gperes7.c */


wideChar negMap[MAX_NODENAME]; /* Map of negatives of ASCII node names
    for speedup */
char opMap[MAX_NODENAME]; /* Map of from ASCII operator to position in
    ALL_BIN_CONNECTIVES for speedup */
wideChar nodeNameMap[MAX_NODENAME]; /* Map from ASCII node name to lattice
    node number for speedup */

/* Binary operation table for fast lookup */
wideChar binOpTable[MAX_BIN_CONNECTIVES][MAX_NODES][MAX_NODES];
wideChar ultraFastBinOpTable[MAX_BIN_CONNECTIVES][MAX_NODENAME]
    [MAX_NODENAME];

/* Special flags for commuting pair option */
char commuteOption; /* Flag that user specified -c program option */
char OADoneFlag; /* Flag for last lattice passing the OA law */
char OMDoneFlag; /* Flag for last lattice passing the OM law */

/* For -v (show lattice points visited) option */
char showVisits = 0; /* Set to 1 to show all
                        lattice points visited by failure.  Useful for
                        identifying unnecessary (redundant) lattice points. */
char visitFlag = 0; /* Used internally when showVisits is 1 */
wideVstring visitList = wideNullString; /* List of nodes visited */

/* For -f (show all failures) option */
char showAllFailures = 0;  /* Set to 1 to show
                        all possible lattice failures.  Useful for comparing
                        lattice behavior of two different equations. */
void usersGreechieDiagrams(void)
{
  /*** Start of user's Greechie diagrams ***/
  /* The first argument of greechie3, if non-blank, is the lattice
     name - otherwise a default name is generated */
  /* The second argument uses the matrix notation in
     Kalmbach, "Orthomodular Lattices", p. 319, with the matrix
     represented as a comma-separated linear string. */

  greechie3("L42 (OM, OA)",
  "1 2 3  3 4 5  5 6 7  7 8 9  9 10 11  11 12 13  13 14 1"
  "  3 15 10  6 16 13  8 17 18  13 19 18  3 20 17");
  /* Alternate numbering for L42 (in oapass.oml): */
  /*
  "1 2 3  1 4 5  1 6 7  1 8 9  2 10 11  4 12 13  6 14 15"
    "  8 16 17  10 12 14  11 16 18  13 16 19  15 16 20");
  */

  greechie3("L40 (OM, OA)",
  "1 2 11  1 3 12  1 4 13  5 6 7  8 9 10  2 5 14"
  "  2 8 15  3 6 16  3 9 17 4 7 18  4 10 19");

  greechie3("Mayet Fig. 5 (OM, OA)",
   "1 2 3  1 4 7  2 5 8  3 6 9  7 12 14  8 10 12  8 11 13  9 13 16  14 15 16");

  greechie3("L38 (OM, non-OA)",
      "1,2,3,"
      "3,4,5,"
      "5,6,7,"
      "7,8,9,"
      "9,10,11,"
      "11,12,13,"
      "13,14,1,"
      "12,15,4,"
      "15,16,17,"
      "17,18,6");

  greechie3("L36 (OM, non-OA)",
  " 1 2 11  1 3 12  4 5 6  4 7 8  5 9 10  1 6 13"
  "  2 7 14  2 9 15  3 8 16  3 10 17");

  greechie3("L36b (OM, non-OA)",
  "1 2 3  1 4 5  2 6 7  3 8 9  4 10 11  5 12 13"
  "  6 10 14  7 12 15 8 11 16  9 13 14  15 16 17");

  greechie3("L$ (OM, non-OA)",
  "1 2 3  3 4 5  5 6 7  7 8 9  9 10 11  11 12 1  10 13 4");

  /*** End of user's Greechie diagrams ***/
} /* usersGreechieDiagrams() */



/******************** Main program *******************************************/

int main(int argc, char *argv[])
{

  vstring str1 = "";
  vstring str2 = "";
  vstring str3 = "";
  long i, j, argOffset;
  char argOffsetChanged;
  vstring contLine = ""; /* Continuation line */
  char printLatticeFlag = 0;

  /* argc is the number of arguments; argv points to array containing them */

  /* Line continuation for DOS: "$x" means get argument x from prompt */
  for (i = 1; i < argc; i++) {
    let(&str1, argv[i]);
    if (str1[0] == '$') {
      if (str1[0] == '\'' || str1[0] == '\"') {
        /* Strip quotes */
        let(&str1, seg(str1, 2, strlen(str1) - 1));
      }
      /* Strip off successive "$x"s and replace with continuation lines */
      while (str1[0] == '$') {
        let(&str2, cat(left(str1, 2), "> ", NULL));
        linput(NULL, str2, &contLine);
        let(&str1, cat(right(str1, 3), contLine, NULL));
      }
      /* Note that we'll just give up and not free the memory argv[i] points
         to; it seems the safest thing to do since it may not be a real malloc
         object depending on compiler */
      /* To be extra safe we might want to clone the argv pointer array first
         before reassigning it; maybe in a future version */
      argv[i] = str1;
      str1 = ""; /* Relinquish string ownership to argv[i] (instead of let()) */
    }
  }
  let(&str1, ""); /* Deallocate string */
  let(&str2, ""); /* Deallocate string */
  let(&contLine, ""); /* Deallocate string */

  if (argc <= 1) {
    /* No arguments means print help */
    printhelp();
    return 0;
  }

  /* Get command line options */
  /* Important: none of the options have the syntax of a legal wff.   This
     should be the case for any future options as well. */
  userArg = 0;
  commuteOption = 0;
  argOffset = 0;
  argOffsetChanged = 1;
  while (argOffsetChanged) {
    argOffsetChanged = 0;
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "--help")) {
      printhelp();
      return 0;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-a")) {
      argOffset++;
      argOffsetChanged = 1;
      userArg = -1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-c")) {
      argOffset++;
      argOffsetChanged = 1;
      commuteOption = 1;
      /* This is not implement for latticeg.c, only lattice.c */
      print2("-c is implemented in lattice.c only\n");
      return 0;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-v")) {
      argOffset++;
      argOffsetChanged = 1;
      showVisits = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-f")) {
      argOffset++;
      argOffsetChanged = 1;
      showAllFailures = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-1")) {
      argOffset++;
      argOffsetChanged = 1;
      oneLineOutput = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-l")) {
      argOffset++;
      argOffsetChanged = 1;
      removeLegs = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-i")) {
      if (stdInputMode) {
        print2("?Error: Both \"-i\" and \"--i\" are not allowed.\n");
        return 0;
      }
      if (argc - argOffset > 2) {
        /* Open the output file */
        fp = fopen(argv[2 + argOffset], "r");
        if (fp == NULL) {
          print2("?Error: Couldn't open the file \"%s\".\n",
              argv[2 + argOffset]);
          return 0;
        }
      } else {
        print2("?Error: No input file specified.\n");
        return 0;
      }
      argOffset += 2;
      argOffsetChanged = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "--i")) {
      if (fp != NULL) {
        print2("?Error: Both \"-i\" and \"--i\" are not allowed.\n");
        return 0;
      }
      argOffset++;
      argOffsetChanged = 1;
      /* Set flag to take input from standard input instead of a file */
      stdInputMode = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-o")) {
      if (argc - argOffset > 2) {
        if (fplog != NULL) {
          print2("?Error: Cannot specify more than one output file.\n");
          return 0;
        }
        /* Open the output file */
        fplog = fSafeOpen(argv[2 + argOffset], "w");
        if (fplog == NULL) {
          return 0;
        }
        /* Disable buffering of the output file so that all partial results
           will be there in case a run is aborted before completion */
        setbuf(fplog, NULL);
      } else {
        print2("?Error: No output log file specified.\n");
        return 0;
      }
      argOffset += 2;
      argOffsetChanged = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "--o")) {
      if (argc - argOffset > 2) {
        if (fplog != NULL) {
          print2("?Error: Cannot specify more than one output file.\n");
          return 0;
        }
        /* Open the output file - append mode */
        fplog = fopen(argv[2 + argOffset], "a");
        if (fplog == NULL) {
          print2("?Error: Couldn't open the file \"%s\".\n",
              argv[2 + argOffset]);
          return 0;
        }
        /* Disable buffering of the output file so that all partial results
           will be there in case a run is aborted before completion */
        setbuf(fplog, NULL);
      } else {
        print2("?Error: No output log file specified.\n");
        return 0;
      }
      argOffset += 2;
      argOffsetChanged = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-n")) {
      if (argc - argOffset > 2) userArg = val(argv[2 + argOffset]);
      if (userArg <= 0  || strcmp(argv[2 + argOffset], str(userArg))) {
        print2("?Error: Expected positive integer after -n\n");
        return 0;
      }
      argOffset += 2;
      argOffsetChanged = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-s")) {
      if (argc - argOffset > 2) startArg = val(argv[2 + argOffset]);
      if (startArg <= 0  || strcmp(argv[2 + argOffset], str(startArg))) {
        print2("?Error: Expected positive integer after -s\n");
        return 0;
      }
      argOffset += 2;
      argOffsetChanged = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-e")) {
      if (argc - argOffset > 2) endArg = val(argv[2 + argOffset]);
      if (endArg <= 0  || strcmp(argv[2 + argOffset], str(endArg))) {
        print2("?Error: Expected positive integer after -e\n");
        return 0;
      }
      argOffset += 2;
      argOffsetChanged = 1;
    }

    /* lattice2gperes7.c */
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-sn")) {
      if (argc - argOffset > 2) startNode = val(argv[2 + argOffset]);
      if (startNode <= 0  || strcmp(argv[2 + argOffset], str(startNode))) {
        print2("?Error: Expected positive integer after -sn\n");
        return 0;
      }
      argOffset += 2;
      argOffsetChanged = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-sp")) {
      if (argc - argOffset > 2) spanNodes = val(argv[2 + argOffset]);
      if (spanNodes <= 0  || strcmp(argv[2 + argOffset], str(spanNodes))) {
        print2("?Error: Expected positive integer after -sp\n");
        return 0;
      }
      argOffset += 2;
      argOffsetChanged = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-ssn")) {
      if (argc - argOffset > 2) secondStartNode = val(argv[2 + argOffset]);
      if (secondStartNode <= 0  || strcmp(argv[2 + argOffset],
          str(secondStartNode))) {
        print2("?Error: Expected positive integer after -ssn\n");
        return 0;
      }
      argOffset += 2;
      argOffsetChanged = 1;
    }
    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-ssp")) {
      if (argc - argOffset > 2) secondSpanNodes = val(argv[2 + argOffset]);
      if (secondSpanNodes <= 0  || strcmp(argv[2 + argOffset],
          str(secondSpanNodes))) {
        print2("?Error: Expected positive integer after -ssp\n");
        return 0;
      }
      argOffset += 2;
      argOffsetChanged = 1;
    }
    /* end lattice2gperes7.c */


    if (argc - argOffset > 1 && !strcmp(argv[1 + argOffset], "-p")) {
      if (argc - argOffset > 2) userArg = val(argv[2 + argOffset]);
      if (userArg <= 0  || strcmp(argv[2 + argOffset], str(userArg))) {
        print2("?Error: Expected positive integer after -p\n");
        return 0;
      }
      printLatticeFlag = 1;
      argOffset += 2;
      argOffsetChanged = 1;
    }
  }

  init(); /* One-time initialization */

  if (printLatticeFlag) {
    /* Print lattice for user */
    i = 0;
    if (fp != NULL) i = i + 2;
    if (fplog != NULL) i = i + 2;
    if (argc != 3 + i) {
      print2(
          "?Error: Only the -i and -o (or --o) options may be used with -p\n");
      return 0;
    }
    initLattice(userArg);
    if (!nodes && userArg > 0) {
      print2("?Error: Lattice %ld does not exist\n", userArg);
      return 0;
    }
    print2("Name of lattice %ld: %s\n", userArg, latticeName);
    print2("Number of nodes, atoms, blocks:  %ld, %ld, %ld\n", nodes, atoms,
        blocks);
    print2("Greechie diagram (with atoms remapped to eliminate gaps):\n");
    print2(" %s\n", greechieStmt);
    print2("The lattice node names are capitalized to indicate complement.\n");
    print2("Beyond letters, numbering is \"#0;\", \"#2;\",... with\n");
    print2("complements \"#1;\", \"#3;\",... .\n");
    print2("\n");
    print2("  Node  Nodes directly below it\n");
    print2("  ----  -----------------------\n");
    for (i = 1; i <= nodes; i++) {
      let(&str1, cat("  ", printableString(wideLeft(nodeList[i], 1)),
          NULL));
      let(&str1, cat(str1, left("     ", 8 - strlen(str1)), NULL));
      /* Inefficient loop end test, but ok since it's only printing */
      for (j = 2; j <= wideLen(nodeList[i]); j++) {
        let(&str1, cat(str1, j == 2 ? "" : ", ",
            printableString(wideMid(nodeList[i], j, 1)), NULL));
      }
      print2("%s\n", str1);
    }

    /* Print a cross-reference table between nodes and atoms */
    print2("\n");
    print2("Cross-referenced between nodes and atoms (internally, the\n");
    print2("atoms are remapped to eliminate numbering gaps):\n");
    print2("\n");
    print2("        Remapped  Original\n");
    print2("  Node  atom      atom\n");
    print2("  ----  --------  --------\n");
    for (i = 1; i <= nodes; i++) {
      let(&str1, cat("  ", printableString(wideLeft(nodeList[i], 1)),
          NULL));
      let(&str1, cat(str1, left("         ", 10 - strlen(str1)), NULL));

      /* Get atom name for user information */
      let(&str2, printableAtomName(nodeToAtom(i)));
      let(&str3, printableAtomName(atomReverseMap[nodeToAtom(i)]));
      let(&str2, cat(str2, left("         ", 9 - strlen(str2)), NULL));
      let(&str3, cat(str3, left("         ", 6 - strlen(str3)), NULL));
      print2("%s %s %s %s\n", str1, str2, str3,
          (i > atoms + 1 && nodeToAtom(i) > 0) ? "(co-atom)" : "" );
    }

    return 0;
  } /* if printLatticeFlag */

  /* Assign user's hypotheses and conclusion */
  hypotheses = argc - 2 - argOffset;
  for (i = 1; i < argc - argOffset; i++) {
    let(&str2, argv[i + argOffset]);
    /* Strip quotes and continuation line backslashes */
    for (j = 0; j < strlen(str2); j++) {
      if (str2[j] == '\'' || str2[j] == '\"' || str2[j] == '\\') {
        let(&str2, cat(left(str2, j), right(str2, j + 2), NULL));
      }
    }
    let(&str2, edit(str2, 1 + 2 + 4)); /* Strip spaces & garbage chars */
    if (i != argc - 1 - argOffset) {
      /* Assign hypothesis */
      let(&(hypList[i - 1]), str2);
    } else {
      /* Assign conclusion */
      let(&conclusion, str2);
    }
  }
  let(&str2, ""); /* Deallocate */

  /* Repeat the hypotheses and conclusion for user verification */
  if (!oneLineOutput) {
    for (i = 0; i < hypotheses; i++) {
      if (i > 0) {
        print2("& ");
      }
      print2("%s ", hypList[i]);
    }
    if (hypotheses > 0) {
      print2("=> ");
    }
    print2("%s\n", conclusion);
  }

  /* Convert to Polish */
  for (i = 0; i < hypotheses; i++) {
    if (strchr(hypList[i], FORALL_OPER) != NULL ||
        strchr(hypList[i], EXISTS_OPER) != NULL) {
      print2("?Error:  Hypotheses may not have quantifiers\n");
      exit(0);
    }
    let(&(polHypList[i]), "");
    polHypList[i] = toPolish(hypList[i]);
  }
  let(&polConclusion, "");
  polConclusion = toPolish(conclusion);

  /* Strip off any quantifiers from equation (assumed to be in prenex
     normal form) */
  j = strlen(polConclusion);
  for (i = j - 1; i >= -1; i--) {
    if (i == -1) break;
    if (strchr(QUANTIFIER_CONNECTIVES, polConclusion[i]) != NULL)
      break;
  }
  let(&quantifiers, "");
  if (i >= 0) {
    /* There are quantifiers; remove and save them */
    let(&quantifiers, left(polConclusion, i + 2));
    let(&polConclusion, right(polConclusion, i + 3));
    if (hypotheses > 0) {
      print2("?Error:  Hypotheses are not permitted when using quantifiers\n");
      exit(0);
    }
    /* For each variable in the conclusion, make sure there is a quantifier;
       otherwise add "for all" at the beginning */
    /* Use separate str1 to accumulate so they'll be added in order of
       first occurrence to make test() evaluate them in this order, so
       user will have a known evaluation order */
    let(&str1, "");
    j = strlen(polConclusion);
    for (i = 0; i < j; i++) {
      if (strchr(VAR_LIST, polConclusion[i]) != NULL) {
        if (strchr(quantifiers, polConclusion[i]) == NULL &&
            strchr(str1, polConclusion[i]) == NULL) {
          let(&str1, cat(str1, chr(FORALL_OPER), chr(polConclusion[i]), NULL));
        }
      }
    }
    let(&quantifiers, cat(str1, quantifiers, NULL));
    /* Separate into quantifier types and variables for later efficiency */
    j = strlen(quantifiers);
    let(&quantifierTypes, space(j / 2));
    let(&quantifierVars, space(j / 2));
    for (i = 0; i < j; i = i + 2) {
      quantifierTypes[i / 2] = quantifiers[i];
      quantifierVars[i / 2] = quantifiers[i + 1];
    }
  } /* If there are quantifiers */
  /* If there are no quanifiers, we'll use the fact that quantifierVars is
     empty as an indicator for it */

  if (!commuteOption) {
    testAllLattices(); /* Run the program */
  } else {
    /* Run -c special option to find potentially commuting pairs  */
    findCommutingPairs();
  }

  return 0;
} /* main */

void printhelp(void)
{
vstring a = "";
print2("\n");
print2("latticeg.c - Orthomodular Lattice Evaluator for Greechie Diagrams\n");
print2("Usage: latticeg [options] <hyp> <hyp> ... <conclusion>\n");
print2("         options:\n");
print2("           -a - test all lattices (don't stop after first failure)\n");
print2(
"           -n <integer> - test only the program's <integer>th lattice\n");
print2(
"           -s <integer> - start at the program's <integer>th lattice\n");
print2(
"           -e <integer> - end at the program's <integer>th lattice\n");

/* lattice2gperes7.c */
print2(
"           -sn <integer> - test each lattice from node <integer>\n");
print2(
"           -sp <integer> - test <integer> nodes (span)\n");
print2(
"           -ssn <integer> - like -sn but for next inner loop level\n");
print2(
"           -ssp <integer> - like -sp but for next inner loop level\n");
print2(
"             e.g. -sn 5 -sp 1 -ssn 6 -ssp 8 = 5th node in outer loop, 6th\n");
print2(
"             node in next inner loop for 8 iterations; -sp must be 1\n");
/* end lattice2gperes7.c */

print2("           -v - show all visits to lattice points in a failure\n");
print2("           -f - show all failures in failing lattice\n");
print2(
"           -1 - print one formatted line per diagram, mainly for piping\n");
print2("           -l - skip (ignore) Greechie diagrams with legs\n");
print2(
"           -i <file> - use Greechie lattices from <file> instead of the\n");
print2(
"                       built-in ones\n");
print2(
"           --i - same as -i but using standard input instead of a file\n");
print2(
"           -o (--o) <file> - write (append) output to <file> as well as screen\n");
print2(
"       latticeg -p <integer> - print the program's <integer>th lattice\n");
print2(
"           (you may use the -i and -o [or --o] options with -p)\n");
print2("       latticeg --help (or no argument) - print this message\n");
print2("Notes: Only one of -a and -n should be used.  -s and -e are applied\n");
print2("before any others.\n");
print2("\n");
print2(
   "Copyright (C) 2009 GPL Norman Megill <nm@alum.mit.edu> Version %s\n",
   VERSION);
/* We really don't need this with Unix; just use "latticego --help | more"
linput(NULL,"Press Enter to continue, q to quit...",&a);
if (toupper(a[0]) == 'Q') goto returnPoint;
*/
print2("\n");
print2("This program checks built-in lattices (hard-coded into the\n");
print2("function 'initLattice') for violation of the user's input\n");
print2("conjecture.  Input formulas may have up to 23 variables\n");
print2("a,b,c,d,e,f,g,h,j,k,l,m,n,p,q,r,s,t,u,w,x,y,z (i,o,v omitted)\n");
print2("and constants 0,1.\n");
print2("\n");
print2("The output is of the form \"<result> <name>\" where <name> is\n");
print2("the lattice name.  An assignment that violates the lattice is\n");
print2("given when the <result> is FAILED.\n");
print2("\n");
print2("To compile for Unix:  Use 'gcc latticeg.c -o latticeg'.  The\n");
print2("entire program is contained in the single file latticeg.c .\n");
print2("\n");
print2("To run:  Type, at the Unix or DOS prompt, \'latticeg <hyp> \n");
print2("<hyp> ... <conclusion>\' where there are zero or more hypotheses\n");
print2("followed by one conclusion.  Each argument may be enclosed in\n");
print2("double or (Unix) single quotes if there is ambiguity.  Example:\n");
print2("\'latticeg \"1<(x#y)\" \"x=y\"\' tests the orthomodular law.\n");
print2("\n");
print2("\n");
print2("\n");
print2("Each <hyp> and the <conclusion> must be a <wff> defined as follows:\n");
print2("\n");
/*
linput(NULL,"Press Enter to continue, q to quit...",&a);
if (toupper(a[0]) == 'Q') goto returnPoint;
*/
print2("\n");
print2("    <var> := a | b | c | d | e | f | g | h | j | k | l | m | n |\n");
print2("                 p | q | r | s | t | u | w | x | y | z\n");
print2("    <opr> := ^ | v | # | O | I | 2 | 3 | 4 | 5 \n");
print2(
"    <const> := 0 | 1           <uopr> := -\n");
print2(
"    <term> := <var> | <const> | <uopr> <term> | ( <term> <opr> <term> )\n");
print2(
"    <brel> := = | < | > | [    <ucon> := ~       <bcon> := & | V | } | :\n");
print2(
"    <wff> := ( <term> <brel> <term> ) | <ucon> <wff> | ( <wff> <bcon> <wff> )\n");
print2("\n");
print2("where a,b,c,... are variables (no i,o,v); 0,1 are constants; and\n");
print2("    - = negation (orthocomplement)\n");
print2("    ^ = conjunction (cap, meet, infimum)\n");
print2("    v = disjunction (cup, join, supremum)\n");
print2("    # = biimplication: ((x^y)v(-x^-y))\n");
print2("    O = ->0 = classical arrow: (-xvy)\n");
print2("    I = ->1 = Sasaki arrow: (-xv(x^y))\n");
print2("    2 = ->2 = Dishkant arrow: (-yI-x)\n");
print2("    3 = ->3 = Kalmbach arrow: (((-x^y)v(-x^-y))v(x^(-xvy)))\n");
print2("    4 = ->4 = non-tollens arrow: (-y3-x)\n");
print2("    5 = ->5 = relevance arrow: (((x^y)v(-x^y))v(-x^-y))\n");
print2(
"and = is equality, < is less-than-or-equal, > is g.e., [ is commutes:\n");
print2("    x<y is (xvy)=y; x>y is y<x; x[y is x=((x^y)v(x^-y)).\n");
print2(
"Metalogical connectives:  ~,&,V,},: are NOT,AND,OR,IMPLIES,EQUIVALENT.\n");
print2("The outermost parentheses of a <wff> are optional.\n");
print2("\n");
/*
linput(NULL,"Press Enter to continue, q to quit...",&a);
if (toupper(a[0]) == 'Q') goto returnPoint;
*/
print2("\n");
print2("Predicate logic:\n");
print2("\n");
print2("The present implementation has the following limitations:\n");
print2("1. No hypotheses may be present if quantifiers are used.\n");
print2("   Use & (AND) and } (IMPLIES) in the conclusion instead.\n");
print2("2. The conclusion must be a <qwff> as defined below.\n");
print2("3. No two quantifiers may be followed by the same variable.\n");
print2("\n");
print2("We extend the wff syntax as follows:\n");
print2("    <qwff> := <wff> | @ <var> <qwff> | ] <var> <qwff>\n");
print2("where quantifier @ means \"for all\" and ] means \"exists\".\n");
print2("\n");
print2("Thus the conclusion must be in prenex normal form, i.e. with all\n");
print2("quantifiers at the beginning of the expression.\n");
print2("\n");
print2(
"Example:  'latticeg \"]x@y(z<(xvy))\"' means \"for all z (implicitly),\n");
print2("there is an x s.t. for all y, z is l.e. xvy.\"\n");
/*
linput(NULL,"Press Enter to continue, q to quit...",&a);
if (toupper(a[0]) == 'Q') goto returnPoint;
*/
print2("\n");
print2("A FAILED result shows the failing assignments with a,b,c... as\n");
print2("lattice points and A,B,C,... as complemented lattice points.\n");
print2("Use the 'latticeg -p' program option to see lattice contents.\n");
print2("\n");
print2("For lattices with more than 48 lattice points, the failing\n");
print2(
"assignments beyond ...x,y,z are shown as #0;,#2;,#4;,...,#10;,...\n");
print2("with complements #1;,#3;,#5;,...\n");
print2("\n");
print2("The Greechie lattice atom numbers 1,2,3,...,23 correspond to nodes\n");
print2("a,b,c,... from the list:\n");
print2("\n");
print2("     a,b,c,d,e,f,g,h,j,k,l,m,n,p,q,r,s,t,u,w,x,y,z\n");
print2("\n");
print2("(with i,o,v omitted) and 24,25,26,... by:\n");
print2("\n");
print2("     decimal #0;,#2;,#4;, ... #100;,...\n");
print2("\n");
print2("#1;, #3;,... are the complements of #0;, #2;,...\n");
print2("\n");
/*
linput(NULL,"Press Enter to continue, q to quit...",&a);
if (toupper(a[0]) == 'Q') goto returnPoint;
*/
print2("\n");
print2("How to handle long equations:\n");
print2("You may specify strings to be replaced by continuation lines using\n");
print2("arguments of the form '$x' where x is a single character.  The\n");
print2("program will prompt with '$x> '; in response you should enter the\n");
print2("corresponding argument (quotes are optional).  Hint:  In Unix\n");
print2("enclose '$x' in single quotes to suppress shell interpretation.\n");
print2("\n");
print2("  latticeg '$1' '$2' \"x=z\"\n");
print2("  $1> x=y\n");
print2("  $2> y=z\n");
print2("\n");
print2("is the same as\n");
print2("\n");
print2("  latticeg \"x=y\" \"y=z\" \"x=z\"\n");
print2("\n");
print2("To break up very long formulas, use '$x$y$z...'; the above is also\n");
print2("the same as:\n");
print2("\n");
print2("  latticeg '$1$2' '$3' \"x=z\"\n");
print2("  $1> x=\n");
print2("  $2> y\n");
print2("  $3> y=z\n");
print2("Note that the character after the '$' is only for the prompt and\n");
print2("is otherwise ignored.  Thus \"latticeg '$a$a' '$a'...\" is\n");
print2("acceptable.\n");
print2("\n");
/*
linput(NULL,"Press Enter to continue, q to quit...",&a);
if (toupper(a[0]) == 'Q') goto returnPoint;
*/
print2("\n");
print2("Using an input file (-i option):\n");
print2("\n");
print2("The input file should have one Greechie diagram per line, with each\n");
print2("atom name a character from the list:\n");
print2("  %s\n", left(ATOM_MAP, 54));
print2("  %s\n", right(ATOM_MAP, 55));
print2("where atom 1 = 1, atom 9 = 9, atom 10 = A, atom 35 = Z,\n");
print2("atom 36 = a, etc. with no gaps in numbering.  Blocks are separated\n");
print2("with a comma, and the last block ends with a period.  Each block\n");
print2("must have 3 or 4 atoms.  For example the diagram on p. 319 of\n");
print2("Kalmbach's _Orthomodular Lattices_ would be\n");
print2("  124,235,167,389.\n");
print2("Use the -p option to see the resulting lattice.\n");
print2("\n");
print2("When the atom list is exhausted, it can be continued by starting\n");
print2("over with a + before each character, then ++, and so on:\n");
print2("  12...9A...Za...`{|}~+1+2...+|+}+~++1...++~+++1....\n");
print2("\n");
print2("If the input diagram has gaps in the atom numbering, it will be\n");
print2("renumbered internally to eliminate the gaps.  The -1 option will\n");
print2("display the renumbered lattice.\n");
/*
returnPoint:
*/
let(&a, ""); /* Deallocate string */
return;
} /* printhelp() */


void testAllLattices(void)
{
  long latticeCase = 0;
  if (userArg > 0) latticeCase = userArg - 1;

  while (1) {
    latticeCase++;
    if (latticeCase > MAX_LATTICES    /* Built-in lattice limit */
        && latticeCase > fileLattices /* External file lattices */
        && !stdInputMode      /* Not in standard input mode */
        && userArg <= 0) break;                   /* Exhausted lattice cases */
    if (stdInputMode == 2) break; /* EOF flag in standard input mode */
    initLattice(latticeCase);
    if (!nodes && userArg > 0) {
      print2("?Error: There is no lattice %ld\n", userArg);
      return;
    }
    if (!nodes) continue; /* Ignore gap in lattice numbering */
    if (test() == TRUE_CONST) {
      if (!oneLineOutput) {
        print2("Passed %s\n", latticeName);
      } else {
        print2("%s passed: %s\n", latticeName, greechieStmt);
      }
    } else {
      if (!showAllFailures && !oneLineOutput) {
        /* (If showAllFailures, failure was printed already by test()) */
        print2("FAILED %s at %s\n", latticeName, failingAssignment);
      }
      if (oneLineOutput) print2("%s failed: %s\n", latticeName, greechieStmt);
      if (userArg == 0) break; /* Default: stop on first failure */
    }
    if (userArg > 0) break; /* User wants to try only one lattice */
  }

  return;
} /* testAllLattices() */

/* This function is called when the user specifies the -c option.
   The hypotheses and conclusion are broken down into subformulas,
   then all subformula pairs are tested to see if they potentially
   commute (i.e. if assuming they commute does not fail the OM
   lattices).  The pairs that potentially commute are printed out. */
void findCommutingPairs(void)
{
  long latticeCase;
  long i, j, subformulas;
  wideChar testResult;
  vstring str1 = "";
  vstring exprList = "";
  vstring subformList = "";
  vstring fromPol1 = "";
  vstring fromPol2 = "";
  char OAOnlyFlag;

  /* Make sure no metalogic is present */
  let(&str1, cat(LOGIC_BIN_CONNECTIVES, chr(NOT_OPER),
      QUANTIFIER_CONNECTIVES, NULL));
  for (j = 0; j < strlen(polConclusion); j++) {
    if (strchr(str1, polConclusion[j]) != NULL) {
      print2("?Error: Metalogic is not implemented for the -c option.\n");
      exit(0);
    }
  }
  for (i = 0; i < hypotheses; i++) {
    for (j = 0; j < strlen(polHypList[i]); j++) {
      if (strchr(str1, polHypList[i][j]) != NULL) {
        print2("?Error: Metalogic is not implemented for the -c option.\n");
        exit(0);
      }
    }
  }
  let(&str1, "");

  print2(
"This is a list of potentially commuting pairs i.e. that pass all OM\n");
  print2(
"lattices with the hypotheses assumed.  Additional pairs that potentially\n");
  print2(
"commute assuming OA are prefixed with '(OA)'.\n");

  /* Build a list with all expressions - abbreviated */
  for (i = 0; i < hypotheses; i++) {
    /* Strip leading '=' before adding to subformula list */
    let(&exprList, cat(exprList, right(polHypList[i], 2), NULL));
  }
  let(&exprList, cat(exprList, right(polConclusion, 2), NULL));

  /* Unabbreviate the hypotheses and conclusion */
  let(&str1, "");
  for (i = 0; i < hypotheses; i++) {
    str1 = unabbreviate(polHypList[i]);
    let(&polHypList[i], str1);
    let(&str1, ""); /* Deallocate from unabbreviate fn call */
  }
  str1 = unabbreviate(polConclusion);
  let(&polConclusion, str1);
  let(&str1, ""); /* Deallocate from unabbreviate fn call */

  /* Build a list with all expressions - unabbreviated */
  /* The unabbreviated expressions obtain additional commute pairs */
  for (i = 0; i < hypotheses; i++) {
    /* Strip leading '=' before adding to subformula list */
    let(&exprList, cat(exprList, right(polHypList[i], 2), NULL));
  }
  let(&exprList, cat(exprList, right(polConclusion, 2), NULL));

  /* Build a list with all subformulas */
  let(&subformList, "");
  subformList = subformulaList(exprList);

  subformulas = numEntries(subformList);
  for (i = 1; i <= subformulas - 1; i++) {
    for (j = i + 1; j <= subformulas; j++) {
      /* Set conclusion to "subformula pair commutes" */
      let(&polConclusion, cat("[", entry(i, subformList),
          entry(j, subformList), NULL));
      latticeCase = 0;
      OAOnlyFlag = 0;
      while (1) {
        latticeCase++;
        initLattice(latticeCase);
        if (latticeCase > MAX_LATTICES)
          bug(10);/* Exhausted lattice cases - means OMDoneFlag
                     was never set */
        if (!nodes) continue; /* Ignore gap in lattice numbering */
        testResult = test();
        if (testResult != TRUE_CONST) break;
           /* Failed - definitely doesn't commute */
        if (OADoneFlag) OAOnlyFlag = 1;
        if (OMDoneFlag) break; /* Did all OM cases */
      }
      if (testResult == TRUE_CONST ||
          OAOnlyFlag) {
        /* The pair potentially commutes - print it out */
        let(&fromPol1, "");
        fromPol1 = fromPolish(entry(i, subformList));
        /* Strip leading and trailing parenths */
        /* if (fromPol1[0] == '(')
          let(&fromPol1, seg(fromPol1, 2, strlen(fromPol1) - 1));*/
        let(&fromPol2, "");
        fromPol2 = fromPolish(entry(j, subformList));
        /* Strip leading and trailing parenths */
        /*if (fromPol2[0] == '(')
          let(&fromPol2, seg(fromPol2, 2, strlen(fromPol2) - 1));*/
        if (testResult != TRUE_CONST)
          let(&fromPol1, cat("(OA) ", fromPol1, NULL));
        if (strlen(fromPol1) + strlen(fromPol2) <= 74) {
          /* Print on one line */
          print2("%s and %s\n", fromPol1, fromPol2);
        } else {
          /* Print on two lines */
          print2("%s and\n  %s\n", fromPol1, fromPol2);
        }
      }
    } /* next j */
  } /* next i */

  let(&str1, "");
  let(&exprList, "");
  let(&subformList, "");
  let(&fromPol1, "");
  let(&fromPol2, "");
  return;
} /* findCommutingPairs() */



void init(void) /* Should be called only once!! */
{
  long i,j;
  vstring tmpStr = "";
  if (fp != NULL) {
    /* The user specified an input file */
    /* Count the lines - each line is a lattice */

    fileLattices = 0;
    while (linput(fp, NULL, &tmpStr)) {
      fileLattices++;
    }
    if (!oneLineOutput)
      print2("The input file has %ld lattice(s).\n", fileLattices);
    rewind(fp);
    fileLineNum = 0;
  }

  /* Check that constants are consistent */
  if (MAX_BIN_CONNECTIVES != strlen(ALL_BIN_CONNECTIVES)) bug(1);
  if (MAX_VARS != strlen(VAR_LIST)) bug(2);
  if (instr(1, ALL_BIN_CONNECTIVES, chr(NEG_OPER))) bug(203);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(INF_OPER))) bug(204);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(SUP_OPER))) bug(205);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(ID_OPER))) bug(206);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(IMP0_OPER))) bug(207);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(IMP1_OPER))) bug(208);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(IMP2_OPER))) bug(209);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(IMP3_OPER))) bug(210);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(IMP4_OPER))) bug(211);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(IMP5_OPER))) bug(212);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(EQ_OPER))) bug(213);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(LE_OPER))) bug(214);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(GE_OPER))) bug(215);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(COM_OPER))) bug(216);
  if (instr(1, ALL_BIN_CONNECTIVES, chr(NOT_OPER))) bug(217);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(AND_OPER))) bug(218);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(OR_OPER))) bug(219);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(IMPL_OPER))) bug(220);
  if (!instr(1, ALL_BIN_CONNECTIVES, chr(BI_OPER))) bug(221);
  if (MAX_NODES <= FALSE_CONST || MAX_NODES <= TRUE_CONST
      || FALSE_CONST == 0 || TRUE_CONST == 0)
    /* Bad FALSE_CONST or TRUE_CONST will overflow binOpTable or
       cause end-of-string problems */
    bug(226);

  /* Convert string constant to wide string "constants" to prevent
     string stack overflow due to wide() */
  wideLet(&WIDE_LOGIC_BIN_CONNECTIVES, wide(LOGIC_BIN_CONNECTIVES));
  wideLet(&WIDE_ALL_BIN_CONNECTIVES, wide(ALL_BIN_CONNECTIVES));

  /* vstring initialization */
  for (i = 0; i < MAX_NODES; i++) {
    nodeList[i] = wideNullString;
    for (j = 0; j < MAX_NODES; j++) {
      sup[i][j] = wideNullString;
    }
  }
  for (i = 0; i < MAX_HYPS; i++) {
    hypList[i] = "";
    polHypList[i] = "";
  }

  /* Initialize speedup table for negative */
  for (i = 'A'; i <= 'z'; i++) {
    if (isupper(i)) {
      negMap[i] = tolower(i);
      /* Extended characters for >23 atoms */
      /*negMap[i + 128] = 128 + tolower(i);*/
    }
    if (islower(i)) {
      negMap[i] = toupper(i);
      /* Extended characters for >23 atoms */
      /*negMap[i + 128] = 128 + toupper(i);*/
    }
  }
  /* Initialize speedup table for extended characters */
  for (i = 128; i < MAX_NODENAME; i += 2) {
    negMap[i] = i + 1;
    negMap[i + 1] = i;
  }

  negMap['0'] = '1';
  negMap['1'] = '0';

  /* Initialize speedup table for operator */
  for (i = 1; i < 128; i++) {
    j = instr(1, ALL_BIN_CONNECTIVES, chr(i));
    if (j != 0) {
      opMap[i] = j - 1;
                 /* Points to location of char in ALL_BIN_CONNECTIVES string */
    } else {
      opMap[i] = 127; /* Not a binary operation */
    }
    let(&tmpStr, ""); /* Deallocate temporary stack to prevent overflow */
  }
  for (i = 128; i < MAX_NODENAME; i++) {
    opMap[i] = 127; /* Not a binary operation */
  }
  ATOM_MAPLen = strlen(ATOM_MAP); /* For + notation */
  /*
  OBSOLETE
  let(&lletterlist, cat("abcdefghjklmnpqrstuwxyz", space(26), NULL));
  let(&uletterlist, cat("ABCDEFGHJKLMNPQRSTUWXYZ", space(26), NULL));
  for (i = 0; i < 26; i++) {
    lletterlist[i + 23] = (i + 'a' + 128) & 0xFF;
    uletterlist[i + 23] = (i + 'A' + 128) & 0xFF;
  }
  */
  /*
  let(&lletterlist, cat("abcdefghjklmnpqrstuwxyz", space(63), NULL));
  let(&uletterlist, cat("ABCDEFGHJKLMNPQRSTUWXYZ", space(63), NULL));
  for (i = 0; i < 63; i++) {
    lletterlist[i + 23] = (i + 1 + 128) & 0xFF;
    uletterlist[i + 23] = (i + 1 + 64 + 128) & 0xFF;
  }
  */
  wideLet(&lletterlist, wideString(MAX_NODES / 2 + 1, (wideChar)'?'));
  wideLet(&uletterlist, wideString(MAX_NODES / 2 + 1, (wideChar)'?'));
  for(i = 0; i < MAX_NODES / 2 + 1; i++) {
    if (i < 23) {
      lletterlist[i] = (wideChar)("abcdefghjklmnpqrstuwxyz"[i]);
      uletterlist[i] = (wideChar)("ABCDEFGHJKLMNPQRSTUWXYZ"[i]);
    } else {
      lletterlist[i] = 128 + (i - 23) * 2;
      uletterlist[i] = 128 + (i - 23) * 2 + 1;
    }
  }

  /* To debug extended characters:  This code makes the extended characters
     the first ones that are used, so the "&" notation can be debugged with
     smaller Greechie diagrams. */
  /*
  OBSOLETE
  let(&lletterlist, cat(space(26), "abcdefghjklmnpqrstuwxyz", NULL));
  let(&uletterlist, cat(space(26), "ABCDEFGHJKLMNPQRSTUWXYZ", NULL));
  for (i = 0; i < 26; i++) {
    lletterlist[i ] = (i + 'a' + 128) & 0xFF;
    uletterlist[i ] = (i + 'A' + 128) & 0xFF;
  }
  */
  /*
  let(&lletterlist, cat(space(63), "abcdefghjklmnpqrstuwxyz", NULL));
  let(&uletterlist, cat(space(63), "ABCDEFGHJKLMNPQRSTUWXYZ", NULL));
  for (i = 0; i < 63; i++) {
    lletterlist[i] = (i + 1 + 128) & 0xFF;
    uletterlist[i] = (i + 1 + 64 + 128) & 0xFF;
  }
  */

} /* init */

void initLattice(long latticeNum)
{
  /* latticeNum:  1 = Boolean lattice, 2 = MO2 lattice, ... */
  long i ,j ,k, p, q, changed;
  wideVstring nname = wideNullString;
  wideVstring nbranch = wideNullString;
  wideVstring big = wideNullString;
  wideVstring small1 = wideNullString;
  wideVstring small2 = wideNullString;
  wideVstring oldsup = wideNullString;
  wideVstring tmpNodeList[MAX_NODES];
  vstring fileLine = "";

  nodes = 0; /* If 0 is returned, lattice is undefined */

  if (endArg && latticeNum > endArg) {
    if (stdInputMode) {
      /* Read and discard the rest of the input stream */
      /*while (linput(fp, NULL, &fileLine));*/ /* necessary? */
      if (stdInputMode != 1) bug(21);
      stdInputMode = 2; /* Set end-of-file flag */
    }
    return;
  }

  /* Initialize flags for special lattices */
  OADoneFlag = 0;
  OMDoneFlag = 0;

  /* Global variables used by greechie3() */
  glatticeNum = latticeNum;
  glatticeCount = 0;

  /* Get the Greechie diagram corresponding to glatticeNum */
  if (fp == NULL && !stdInputMode) {
    /* Use the ones hard-coded into this program */
    usersGreechieDiagrams();
  } else {
    /* We read from an input file or standard input */
    /* Trick greechie3() into thinking we've already done latticeNum cases */
    glatticeCount = latticeNum - 1;
    /* Call greechie3() as if this were a hard-coded user lattice */
    if (latticeNum <= fileLattices || stdInputMode) {
      if (stdInputMode) {
        if (stdInputMode != 1) bug(16);
        fileLattices = latticeNum;
      }
      /* The program should never try to read "backwards" */
      if (fileLineNum >= latticeNum) bug(13);
      /* Skip any input lines before latticeNum in case of -n,-p options */
      while (fileLineNum < latticeNum - 1) {
        fileLineNum++;
        /* Note:  in stdInputMode, fp is NULL telling linput() to use stdin */
        if (!linput(fp, NULL, &fileLine)) {
          if (stdInputMode) {
            if (stdInputMode != 1) bug(17);
            stdInputMode = 2; /* Set end-of-file flag */
            if (nodes) bug(18);
            return;
          }
          bug(14); /* Beyond EOF */
        }
      }
      /* Read the line we're interested in */
      fileLineNum++;
      if (!linput(fp, NULL, &fileLine)) {
        if (stdInputMode) {
          if (stdInputMode != 1) bug(19);
          stdInputMode = 2; /* Set end-of-file flag */
          if (nodes) bug(20);
          return;
        }
        bug(15); /* Beyond EOF */
      }
      greechie3("", fileLine);
    }
  }

  if (!nodes) return;
  if (nodes >= MAX_NODES) bug(8);

  /* Node name list */
  wideLet(&nodeNames, wideString(nodes, (wideChar)'?'));
  for (i = 0; i < MAX_NODENAME; i++) {
    /* Initialize for consistent debugging (theoretically unnecessary) */
    nodeNameMap[i] = 0;
  }
  for (i = 1; i <= nodes; i++) {
    nodeNames[i - 1] = nodeList[i][0];
    /* Initialize speed-up lookup table */
    nodeNameMap[nodeList[i][0]] = i;
  }

  /* Fill out ordering table */
  for (i = 1; i <= nodes; i++) {
    tmpNodeList[i] = wideNullString;
    wideLet(&(tmpNodeList[i]), nodeList[i]);
  }
  changed = 1;
  while (changed) {
    changed = 0;
    for (i = 1; i <= nodes; i++) {
      for (j = 1; j <= nodes; j++) {
        if (i != j) {
          wideLet(&nname, wideLeft(tmpNodeList[j], 1));
          p = wideChrInStr(2, tmpNodeList[i], nname[0]);
          if (p != 0) {
            for (k = 2; k <= wideLen(tmpNodeList[j]); k++) {
              wideLet(&nbranch, wideMid(tmpNodeList[j], k, 1));
              q = wideChrInStr(2, tmpNodeList[i], nbranch[0]);
              if (q == 0) {
                changed = 1;
                wideLet(&(tmpNodeList[i]), wideCat(tmpNodeList[i],
                    nbranch, NULL));
              } /* end if */
            } /* next k */
          } /* end if */
        } /* end if */
      } /* next j */
    } /* next i */
  } /* next while */

  /* Build supremum (disjunction) table */
  for (i = 1; i <= nodes; i++) {
    for (j = 1; j <= nodes; j++) {
      wideLet(&(sup[i][j]), wideString(1, (wideChar)'1'));
    } /* next j */
  } /* next i */
  for (i = 1; i <= nodes; i++) {
    wideLet(&big, wideLeft(tmpNodeList[i], 1));
    for (j = 1; j <= wideLen(tmpNodeList[i]); j++) {
      for (k = 1; k <= wideLen(tmpNodeList[i]); k++) {
        wideLet(&small1, wideMid(tmpNodeList[i], j, 1));
        wideLet(&small2, wideMid(tmpNodeList[i], k, 1));
        wideLet(&oldsup, sup[wideChrInStr(1, nodeNames, small1[0])]
            [wideChrInStr(1, nodeNames, small2[0])]);
        /* oldsup > big */
        if (wideChrInStr(2, tmpNodeList[
            wideChrInStr(1, nodeNames, oldsup[0])], big[0])) {
          wideLet(&(sup[wideChrInStr(1, nodeNames, small1[0])]
              [wideChrInStr(1, nodeNames, small2[0])]), big);
        } /* end if */
      } /* next k */
    } /* next j */
  } /* next i */

  /* Debug */
  /*
  for (i = 1; i <= nodes; i++) {
    for (j= 1; j <= nodes; j++) {
      print2("%s",sup[i][j]);
    }
    print2("\n");
  }
  */

  /* Build table with all binary operations for fast lookup */
  for (i = 0; i < strlen(ALL_BIN_CONNECTIVES); i++) {
    if (strchr(LOGIC_BIN_CONNECTIVES, ALL_BIN_CONNECTIVES[i]) == NULL) {
      for (j = 1; j <= nodes; j++) {
        for (k = 1; k <= nodes; k++) {
          binOpTable[i][j][k] = lookupBinOp(
              (wideChar)(ALL_BIN_CONNECTIVES[i]),
              nodeNames[j - 1],
              nodeNames[k - 1]);
          /* Build even faster table with all binary operations for fast
             lookup */
          /* Eliminates subscript indirections */
          ultraFastBinOpTable[i][nodeNames[j - 1]]
              [nodeNames[k - 1]] =
              binOpTable[i][j][k];
        } /* next k */
      } /* next j */
    } else {
      /* Build tables for metalogical connectives */
      for (j = FALSE_CONST; j <= TRUE_CONST;
          j = j + (TRUE_CONST - FALSE_CONST)) {
        for (k = FALSE_CONST; k <= TRUE_CONST;
            k = k + (TRUE_CONST - FALSE_CONST)) {
          binOpTable[i][j][k] = lookupBinOp(
              (wideChar)(ALL_BIN_CONNECTIVES[i]), j, k);
          /* Build even faster table with all binary operations for fast
             lookup */
          /* Eliminates subscript indirections */
          /* For metalogical constants, the table is the same as
             binOpTable */
          ultraFastBinOpTable[i][j][k] =
              binOpTable[i][j][k];
        } /* next k */
      } /* next k */
    } /* next j */
  } /* next i */

  /* Deallocate strings */
  for (i = 1; i <= nodes; i++) {
    wideLet(&(tmpNodeList[i]), wideNullString);
  }
  wideLet(&nname, wideNullString);
  wideLet(&nbranch, wideNullString);
  wideLet(&big, wideNullString);
  wideLet(&small1, wideNullString);
  wideLet(&small2, wideNullString);
  wideLet(&oldsup, wideNullString);
  let(&fileLine, "");

} /* initLattice() */


/* Converts a Greechie height 3 lattice, using the matrix notation in
   Kalmbach, "Orthomodular Lattices", p. 319, and populates the
   nodes variable and the nodeList array.  glattice is a comma-separated
   list of all nodes, with rows (assumed to be width 3) placed after
   each other. */
void greechie3(vstring name, vstring glattice) {
  long atom, atom2, msize, legs, i, j, k, m, n;
  vstring jptr;
  vstring glattice1 = "";
  vstring str1 = "";
  vstring str2 = "";
  long extendedNotationOffset; /* For + notation */
  wideVstring atomRemap = wideNullString; /* To fill in atom gaps */
  /*** These are now global
  long atoms;
  long block[MAX_BLOCKS + 1][MAX_BLOCK_SIZE + 1];
  long blockSize[MAX_BLOCKS + 1];
  long block4Offset[MAX_BLOCKS + 1];
  long blocks;
  ***/

  glatticeCount++;  /* Global variable */
  if (glatticeCount != glatticeNum) return; /* Early exit if not the one */
  if (startArg && glatticeNum < startArg) return;

  /* In case of temp alloc of glattice; also trim leading, trailing spaces */
  /* Also trim CR in case of DOS file read in Unix */
  let(&glattice1, edit(glattice, 8 + 128 + 4));

  /* Assign the lattice name */
  if (name[0] == 0) {
    /* Blank argument - assign default name */
    let(&latticeName, cat("#", str(glatticeNum), NULL));
  } else {
    let(&latticeName, name); /* User's name */
  }

  if (/*oneLineOutput ||*/ removeLegs)
    print2("%s original: %s\n", latticeName, glattice1);

  /* Parse the input string describing the lattice */

  /* if (instr(1, glattice1, ".") == 0) { */
  if (strchr(glattice1, '.') == NULL) {
    if (glattice1[0] == 0) {
      print2("%s: %s\n", latticeName, glattice1);
      print2("?Error: Blank lines are not allowed.\n");
      exit(0);
    }
    /* No period - assume old standard:  3-atom blocks */
    /* We don't bother to optimize string operations for the old standard */

    /* The following code allows free-formatted lists with spaces and/or
       commas as delimiters */
    i = 0;
    while (glattice1[i]) { /* Convert commas to spaces */
      if (glattice1[i] == ',') glattice1[i] = ' ';
      i++;
    }
    let(&glattice1, edit(glattice1, 8 + 16 + 128)); /* Reduce & trim spaces */
    i = 0;
    while (glattice1[i]) { /* Convert spaces to commas */
      if (glattice1[i] == ' ') glattice1[i] = ',';
      i++;
    }

    msize = numEntries(glattice1); /* Total matrix entries (nx3 matrix) */
    if ((msize / 3) * 3 != msize) {
      print2("%s: %s\n", latticeName, glattice1);
      print2(
"?Error: Number of Greechie matrix entries not factor of 3 (or missing '.')\n");
      exit(0);
    }
    blocks = msize / 3;
    atoms = 0;
    for (i = 1; i <= msize; i++) {
      j = val(entry(i, glattice1));
      let(&str1, ""); /* Purge temp alloc in entry() */
      if (j <= 0) {
        print2("%s: %s\n", latticeName, glattice1);
        print2(
"?Error: Greechie matrix nodes must be numbers > 1 (or missing '.')\n");
        exit(0);
      }
      if (j > atoms) atoms = j;
    }

    for (i = 1; i < msize; i = i + 3) {
      blockSize[(i + 2) / 3] = 3; /* Fixed block size of 3 */
      for (j = 0; j < 3; j++) {
        block[(i + 2) / 3][j + 1] = val(entry(i + j, glattice1));
      }
    }
  } else {
    /* glattice1 has period - assume new (Brendan) compact standard */

    /* let(&glattice1, edit(glattice1, 2)); */ /* Remove spaces */
    /* Remove the above line for speed; the program input should ensure this */
    if (strchr(glattice1, ' ') != NULL) {
      print2("%s: %s\n", latticeName, glattice1);
      print2("?Error: The diagram may not contain spaces\n");
      exit(0);
    }

    n = strlen(glattice1);

    if (glattice1[n - 1] != '.') {
      print2("%s: %s\n", latticeName, glattice1);
      print2("?Error: Last character should be a period\n");
      exit(0);
    }

    /* if (instr(1, left(glattice1, n - 1), ".") != 0) { */
    if (strchr(glattice1, '.') != glattice1 + n - 1) {
      print2("%s: %s\n", latticeName, glattice1);
      print2("?Error: Period can only be last character\n");
      exit(0);
    }
    if (n == 1) {
      print2("%s: %s\n", latticeName, glattice1);
      print2("?Error: Diagram must have at least one block\n");
      exit(0);
    }

    atoms = 0;
    blocks = 1;
    blockSize[blocks] = 0;
    extendedNotationOffset = 0; /* For + notation */
    for (i = 0; i < n; i++) {
      if (glattice1[i] == ',' || glattice1[i] == '.') {
        /* End of block */
        if (blockSize[blocks] < MIN_BLOCK_SIZE) {
          print2("%s: %s\n", latticeName, glattice1);
          print2(
            "?Error: Block %ld has %ld atoms, but minimum block size is %ld\n",
              blocks, blockSize[blocks], (long)MIN_BLOCK_SIZE);
          exit(0);
        }
        if (glattice1[i] == ',') {
          /* Start of new block */
          blocks++;
          if (blocks > MAX_BLOCKS) {
            print2("%s: %s\n", latticeName, glattice1);
            print2(
   "?Error: Maximum blocks allowed is %ld.  Increase MAX_BLOCKS in program.\n",
                (long)MAX_BLOCKS);
            exit(0);
          }
          blockSize[blocks] = 0;
        }
        continue;
      }

      if (glattice1[i] == '+') {
        /* Process the extended notation
           12...9A...Za...`{|}~+1+2...+|+}+~++1...++~+++1....
           From 23-Apr-2009 email to Mladen:
             "If in the far future we get to say 10000 atoms, that would be
             around 100 +'s per atom, obviously extremely inefficient.  But,
             we still have "0" unused, and can have an alternate (and
             compatible) notation where "0" is the start of a decimal number,
             with some non-digit, say ".", terminating it.  I'll leave a
             comment to that effect in the latticeg.c file, for when it
             becomes a problem for a future generation" */
        extendedNotationOffset += ATOM_MAPLen;
        continue;
      }

      /* Get the atom number */
      /*j = instr(1, ATOM_MAP, chr(glattice1[i]));*/
      /*let(&str1, "");*/ /* Deallocate chr call */
      jptr = strchr(ATOM_MAP, glattice1[i]);
      /* if (j == 0) { */
      if (jptr == NULL) {
        print2("%s: %s\n", latticeName, glattice1);
        print2("?Error: Illegal character '%c' in diagram\n", glattice1[i]);
        exit(0);
      }
      j = jptr - ATOM_MAP + 1; /* Atom number */

      j += extendedNotationOffset; /* For + notation */
      extendedNotationOffset = 0; /* For + notation */
      blockSize[blocks]++;
      if (blockSize[blocks] > MAX_BLOCK_SIZE) {
        print2("%s: %s\n", latticeName, glattice1);
        print2(
           "?Error: Block %ld has %ld atoms, but maximum block size is %ld \n",
             blocks, blockSize[blocks], (long)MIN_BLOCK_SIZE);
        exit(0);
      }
      /* Assign the atom */
      block[blocks][blockSize[blocks]] = j;
      if (j > atoms) atoms = j; /* Maximum atom number */
    } /* next i */
  } /* glattice1 has a period (new compact standard) */

  for (i = 1; i <= blocks; i++) {
    for (j = 1; j <= blockSize[i] - 1; j++) {
      for (k = j + 1; k <= blockSize[i]; k++) {
        if (block[i][j] == block[i][k]) {
          print2("%s: %s\n", latticeName, glattice1);
          print2("?Error: Duplicate Greechie atom numbers in a block\n");
          exit(0);
        }
      }
    }
  }

  /* Special function:  see if diagram has 1 or more "legs" i.e. a block
     of rank 1. */
  /* This function also checks to see that 2-atom blocks are disconnected. */
  legs = 0;
  if (/*oneLineOutput ||*/ removeLegs) {
    for (i = 1; i <= blocks; i++) {
      n = 0; /* rank of block */
      for (j = 1; j <= blockSize[i]; j++) {
        /* Scan all other blocks for atom block[i][j] */
        for (k = 1; k <= blocks; k++) {
          if (k == i) continue;
          for (m = 1; m <= blockSize[k]; m++) {
            if (block[i][j] == block[k][m]) {
              if (blockSize[i] == 2 || blockSize[k] == 2) {
                print2("%s: %s\n", latticeName, glattice1);
                print2("?Error: Connected 2-atom blocks are not allowed\n");
                exit(0);
              }
              n++; /* Increase rank */
              goto exit_scan;
            }
          }
        }
       exit_scan:
        continue;
      }
      if (n == 1) {
        /* This is a foot */
        legs = 1; /* Means at least one foot */
        break;
      }
    } /* next i */
  }

  /* Count gaps in atom numbering */
  let(&str1, string(atoms + 1, '0'));
  for (i = 1; i <= blocks; i++) {
    for (j = 1; j <= blockSize[i]; j++) {
      str1[block[i][j]] = '1';
    }
  }
  n = 0; /* Number of gaps in atom numbering */
  for (i = 1; i <= atoms; i++) {
    if (str1[i] == '0') n++;
  }
  /* Error if gaps in numbering */
  /* 24-Apr-09 - gaps in atom numbering are now allowed */
  /*
  if (n > 0) {
    print2("%s: %s\n", latticeName, glattice1);
    print2("?Error: There are gaps in atom numbering\n");
    exit(0);
  }
  */


  wideLet(&atomReverseMap, wideString(atoms + 1, '?'));
  /* If there are gaps, remap the atoms to fill in the gaps */
  if (n > 0) {
    wideLet(&atomRemap, wideString(atoms + 1, '?'));
    j = 0;
    for (i = 1; i <= atoms; i++) {
      if (str1[i] == '1') {
        j++; /* Atom is used */
        atomRemap[i] = j;
        atomReverseMap[j] = i; /* To correlate to input diagram */
      }
    }
    if (atoms - j != n) bug(24); /* Sanity check */
    atoms = j; /* True number of atoms, with no gaps */
    for (i = 1; i <= blocks; i++) {
      for (j = 1; j <= blockSize[i]; j++) {
        block[i][j] = atomRemap[block[i][j]];
      }
    }
    wideLet(&atomRemap, wideNullString); /* Deallocate memory */
  } else {
    /* There is no remapping needed; make the reverse map the identity fn. */
    for (i = 1; i <= atoms; i++) {
      atomReverseMap[i] = i;
    }
  }
  atomReverseMap[0] = 0; /* In case non-atoms 0 or 1 are used */


  /* This is the global greechie diagram for use wherever
     we want to print it out. */
  /* if (instr(1, glattice1, ".") == 0 */
  if (strchr(glattice1, '.') == NULL
                          /* No period - assume old standard:  3-atom blocks */
         || n > 0) {
             /* Also, if there are atom numbering gaps, rewrite the diagram. */
    /* First, compute the size of the new diagram */
    m = 0;
    for (i = 1; i <= blocks; i++) {
      for (j = 1; j <= blockSize[i]; j++) {
        k = block[i][j];
        while (k > ATOM_MAPLen) {
          /* Handle extended notation */
          m++;
          k -= ATOM_MAPLen;
        }
        m++;
      }
      m++;
    }
    let(&greechieStmt, space(m)); /* Preallocate string to computed size */
    /* Next, fill in the characters */
    m = 0;
    for (i = 1; i <= blocks; i++) {
      for (j = 1; j <= blockSize[i]; j++) {
        k = block[i][j];
        while (k > ATOM_MAPLen) {
          /* Handle extended notation */
          greechieStmt[m] = '+';
          m++;
          k -= ATOM_MAPLen;
        }
        greechieStmt[m] = ATOM_MAP[k - 1];
        m++;
      }
      if (i < blocks) {
        greechieStmt[m] = ',';
        m++;
      } else {
        greechieStmt[m] = '.';
        m++;
      }
    }
    if (greechieStmt[m] != 0) bug(25); /* Must be end of string */
  } else {
    /* It is already in the new compact form */
    let(&greechieStmt, glattice1);
  }


  nodes = (atoms * 2) + 2;
  n = atoms;
  for (i = 1; i <= blocks; i++) {
    /* Add 6 nodes for each 4-atom block */
    block4Offset[i] = 0;
    if (blockSize[i] == 4) {
      block4Offset[i] = n;
      nodes = nodes + 6;
      n = n + 3;
    }
  }
  /* Enhance lattice name with atom/block/node count */
  let(&latticeName, cat(latticeName, " (", str(atoms), "/", str(blocks),
      "/", str(nodes), ")", NULL));

  if (removeLegs && legs > 0) {
    if (!oneLineOutput) print2("%s >0 legs, skipped: %s\n", latticeName,
        greechieStmt);
    nodes = 0; /* Force lattice to be skipped */
    goto returnPoint;
  }

  if (nodes > MAX_NODES - 1) {
    print2("%s: %s\n", latticeName, greechieStmt);
    print2("?Error: Greechie diagram %s has more than %ld nodes\n",
        latticeName, (long)(MAX_NODES - 1));
    nodes = 0;  /* Force lattice to be skipped */
    goto returnPoint;
  }

  /* Assign the unit node - all complemented atoms go below it */
  wideLet(&(nodeList[1]), wideCat(wideString(1, (wideChar)'1'),
      wideLeft(uletterlist, atoms), NULL));

  /* Assign the zero node below all uncomplemented atoms */
  for (i = 1; i <= atoms; i++) {
    wideLet(&(nodeList[i + 1]), wideCat(wideMid(lletterlist, i, 1),
        wideString(1,(wideChar)'0'), NULL));
  }

  /* Assign the zero node */
  wideLet(&(nodeList[atoms + 2]), wideString(1, (wideChar)'0'));

  /* Create complemented atom list */
  for (i = 1; i <= atoms; i++) {
    wideLet(&(nodeList[atoms + 2 + i]), wideMid(uletterlist, i, 1));
  }

  /* Create extra nodes for 4-atom blocks */
  for (i = 1; i <= blocks; i++) {
    if (blockSize[i] == 4) {
      for (j = 0; j < 3; j++) {
        wideLet(&(nodeList[2 * block4Offset[i] + 2 + 2*j + 1]),
            wideMid(uletterlist, block4Offset[i] + j + 1, 1));
        wideLet(&(nodeList[2 * block4Offset[i] + 2 + 2*j + 2]),
            wideMid(lletterlist, block4Offset[i] + j + 1, 1));
      }
      /* t */
      wideLet(&(nodeList[2 * block4Offset[i] + 2 + 1]), wideCat(
          wideMid(lletterlist, block4Offset[i] + 1, 1),
          wideMid(lletterlist, block[i][1], 1),
          wideMid(lletterlist, block[i][2], 1), NULL));
      /* u */
      wideLet(&(nodeList[2 * block4Offset[i] + 2 + 2]), wideCat(
          wideMid(lletterlist, block4Offset[i] + 2, 1),
          wideMid(lletterlist, block[i][1], 1),
          wideMid(lletterlist, block[i][3], 1), NULL));
      /* v */
      wideLet(&(nodeList[2 * block4Offset[i] + 2 + 3]), wideCat(
          wideMid(lletterlist, block4Offset[i] + 3, 1),
          wideMid(lletterlist, block[i][1], 1),
          wideMid(lletterlist, block[i][4], 1), NULL));
      /* t' */
      wideLet(&(nodeList[2 * block4Offset[i] + 2 + 4]), wideCat(
          wideMid(uletterlist, block4Offset[i] + 1, 1),
          wideMid(lletterlist, block[i][3], 1),
          wideMid(lletterlist, block[i][4], 1), NULL));
      /* u' */
      wideLet(&(nodeList[2 * block4Offset[i] + 2 + 5]), wideCat(
          wideMid(uletterlist, block4Offset[i] + 2, 1),
          wideMid(lletterlist, block[i][2], 1),
          wideMid(lletterlist, block[i][4], 1), NULL));
      /* v' */
      wideLet(&(nodeList[2 * block4Offset[i] + 2 + 6]), wideCat(
          wideMid(uletterlist, block4Offset[i] + 3, 1),
          wideMid(lletterlist, block[i][2], 1),
          wideMid(lletterlist, block[i][3], 1), NULL));
    }
  }

  /* Process Boolean blocks */
  for (i = 1; i <= blocks; i++) {
    if (blockSize[i] == 3) {
      for (j = 1; j <= 3; j++) {
        atom = block[i][j];
        for (k = 1; k <= 3; k++) {
          if (k == j) continue;
          atom2 = block[i][k];
          wideLet(&(nodeList[atoms + atom + 2]),
              wideCat(nodeList[atoms + atom + 2],
              wideMid(lletterlist, atom2, 1), NULL));
        }
      }
      continue;
    }
    if (blockSize[i] == 4) {
      wideLet(&(nodeList[atoms + block[i][1] + 2]),
          wideCat(nodeList[atoms + block[i][1] + 2],
          wideMid(uletterlist, block4Offset[i] + 1, 1),
          wideMid(uletterlist, block4Offset[i] + 2, 1),
          wideMid(uletterlist, block4Offset[i] + 3, 1), NULL));
      wideLet(&(nodeList[atoms + block[i][2] + 2]),
          wideCat(nodeList[atoms + block[i][2] + 2],
          wideMid(uletterlist, block4Offset[i] + 1, 1),
          wideMid(lletterlist, block4Offset[i] + 2, 1),
          wideMid(lletterlist, block4Offset[i] + 3, 1), NULL));
      wideLet(&(nodeList[atoms + block[i][3] + 2]),
          wideCat(nodeList[atoms + block[i][3] + 2],
          wideMid(lletterlist, block4Offset[i] + 1, 1),
          wideMid(uletterlist, block4Offset[i] + 2, 1),
          wideMid(lletterlist, block4Offset[i] + 3, 1), NULL));
      wideLet(&(nodeList[atoms + block[i][4] + 2]),
          wideCat(nodeList[atoms + block[i][4] + 2],
          wideMid(lletterlist, block4Offset[i] + 1, 1),
          wideMid(lletterlist, block4Offset[i] + 2, 1),
          wideMid(uletterlist, block4Offset[i] + 3, 1), NULL));
      continue;
    }
    bug(9);
  }

 returnPoint:
  let(&str1, ""); /* Deallocate */
  let(&str2, ""); /* Deallocate */
  let(&glattice1, ""); /* Deallocate */

} /* greechie3 */



/* Returns TRUE_CONST if matrix test passed, FALSE_CONST if failed */
/* When FALSE_CONST is returned, the string failingAssignment has the
   assignment that violates the lattice */
wideChar test(void)
{
  long i, j, k, conclusionLen, p, maxDepth, loopDepth;
  wideChar e;
  wideVstring trialConclusion = wideNullString;
  wideVstring trialHypList[MAX_HYPS];
#if defined(PEVAL)
  /******* Partial evaluation speedup *******/
  /* Arrays for partial evaluation 7/18/00 */
  wideVstring trialHypListP[MAX_HYPS][MAX_VARS];
  wideVstring trialConclusionP[MAX_VARS];
  vstring unassignedHypVarsP[MAX_HYPS][MAX_VARS];
  vstring unassignedConclVarsP[MAX_VARS];
  long hypLenP[MAX_HYPS][MAX_VARS];
  long conclusionLenP[MAX_VARS];
  /* Temporary variables for local speedup */
  long tmplen;
  char* tmpuav;
  char* tmpuav1;
  wideVstring tmptrialeq;
  wideVstring tmptrialeq1;
  long tmploopv;
  long tmpvarord;
  long totA = 0, totB = 0, totC = 0;
#else
#endif
  long loopVar[MAX_VARS];
  vstring fromPol = "";
  long hypLen[MAX_HYPS];
  long maxHypVar[MAX_HYPS];
  long maxConclusionVar;
  vstring tmpStr = "";
  wideVstring tmpWide = wideNullString;
  vstring tmpStr2 = "";
  vstring varOrder = "";
  char atLeastOneFailure = 0; /* Used in conjunction with showAllFailures */
  long n;
  vstring tmpStr3 = "";
  vstring tmpStr4 = "";
  vstring tmpStr5 = "";

  /* lattice2gperes.c */
  long enNode = 0;
  long secondEnNode = 0;
  /* end of lattice2gperes.c */

  /* Local string array initialization */
  for (i = 0; i < hypotheses; i++) {
    trialHypList[i] = wideNullString;
  }

  /* Initialization */
  wideLet(&trialConclusion, wide(polConclusion));
  conclusionLen = strlen(polConclusion);
  for (i = 0; i < hypotheses; i++) {
    wideLet(&(trialHypList[i]), wide(polHypList[i]));
    hypLen[i] = strlen(polHypList[i]);
  }

  /* Build a list of all variables found to determine best scanning order */
  /* This way, failures in early hypotheses with few variables can be used
     to skip evaluations of later hypotheses and conclusion for speed-up */
  /* (We assume the user places hypotheses in order of fewest variables
     or most likelihood of failure first) */
  let(&varOrder, "");
  for (i = 0; i < hypotheses; i++) {
    maxHypVar[i] = -1;
    for (p = 1; p <= hypLen[i]; p++) {
      let(&tmpStr, mid(polHypList[i], p, 1));
      j = instr(1, VAR_LIST, tmpStr);
      if (j != 0) { /* It's a variable */
        if (instr(1, varOrder, tmpStr) == 0) { /* but not in list */
          let(&varOrder, cat(varOrder, tmpStr, NULL)); /* then add to list */
        }
        /* Find out where it is in the list */
        j = instr(1, varOrder, tmpStr) - 1;
        if (j < 0) bug(3);
        /* Save the highest variable in the hypothesis for later speedup */
        if (j > maxHypVar[i]) maxHypVar[i] = j;
      }
    }
  }
  maxConclusionVar = -1;
  /* Since hypotheses aren't allowed with quantified formulas, we don't
     have to do this above.  Without hypotheses, the varOrder will
     be exactly in quantifierVars order - this is important for
     algorithm to work. */
  if (quantifierVars[0] != 0) {
    /* Predicate logic */
    k = strlen(quantifierVars);
  } else {
    /* Propositional logic only */
    k = conclusionLen;
  }
  for (p = 1; p <= k; p++) {
    if (quantifierVars[0] != 0) {
      let(&tmpStr, mid(quantifierVars, p, 1));
    } else {
      let(&tmpStr, mid(polConclusion, p, 1));
    }
    j = instr(1, VAR_LIST, tmpStr);
    if (j != 0) { /* It's a variable */
      if (instr(1, varOrder, tmpStr) == 0) { /* but not in list */
        let(&varOrder, cat(varOrder, tmpStr, NULL)); /* then add to list */
      }
      /* Find out where it is in the list */
      j = instr(1, varOrder, tmpStr) - 1;
      if (j < 0) bug(4);
      /* Save the highest variable in the conclusion for later speedup */
      if (j > maxConclusionVar) maxConclusionVar = j;
    }
  }
  maxDepth = strlen(varOrder) - 1;
  if (quantifierVars[0] != 0) {
    /* If quantified, there are no hypotheses so the below should never
       be the case. */
    if (maxConclusionVar != maxDepth) bug(270);
  }
#if defined(PEVAL)
  /******* Partial evaluation speedup *******/
  /* String array initialization for partial evaluations - allocate
     all to maximum length */
  for (i = 0; i <= maxDepth + 1; i++) {
    for (j = 0; j < hypotheses; j++) {
      trialHypListP[j][i] = wideNullString;
      unassignedHypVarsP[j][i] = "";
      /* ??? question 28-Apr-2009 nm: why are we using orig. polHypList
         here but the trial version trialConclusion below? */
      wideLet(&(trialHypListP[j][i]), wide(polHypList[j]));
      let(&(unassignedHypVarsP[j][i]), space(hypLen[j]));
    }
    trialConclusionP[i] = wideNullString;
    unassignedConclVarsP[i] = "";
    wideLet(&(trialConclusionP[i]), trialConclusion);
    let(&(unassignedConclVarsP[i]), space(conclusionLen));
  }
  /* Assign 'y' to all (unevaluated) variables and 'n' to nodes (only
     0 or 1 at this point) and 'u' (uneval. subexpr.) to everything else.
     Do depth 0 only; others will be copied down. */
  for (i = 0; i < hypotheses; i++) {
    for (j = 0; j < hypLen[i]; j++) {
      k = (polHypList[i])[j];
      if (strchr(varOrder, k) != NULL) {
        (unassignedHypVarsP[i][0])[j] = 'y';
      } else {
        if (strchr("01", k) != NULL) {
          (unassignedHypVarsP[i][0])[j] = 'n';
        } else {
          (unassignedHypVarsP[i][0])[j] = 'u';
        }
      }
    }
    hypLenP[i][0] = hypLen[i];
  }
  for (i = 0; i < conclusionLen; i++) {
    j = polConclusion[i];
    if (strchr(varOrder, j) != NULL) {
      (unassignedConclVarsP[0])[i] = 'y';
    } else {
      if (strchr("01", j) != NULL) {
        (unassignedConclVarsP[0])[i] = 'n';
      } else {
        (unassignedConclVarsP[0])[i] = 'u';
      }
    }
  }
  conclusionLenP[0] = conclusionLen;
  /* Initialize all loop variables so any unused ones due to early
     exit will have known assignments for failure displays */
  for (i = 0; i <= maxDepth; i++) {
    loopVar[i] = 0;
  }
#else
#endif


  /* Perform all possible evaluations */
  loopDepth = 0;
  loopVar[loopDepth] = 0;

  /* lattice2gperes7.c */
  enNode = nodes;
  secondEnNode = nodes;
  if (startNode > 0 || spanNodes > 0) {
    if (startNode == 0 || startNode > nodes) {
      print2("?Error: -sn node must be from 1 to  %ld\n", nodes);
      exit(0);
    }
    if (spanNodes == 0) {
      print2("?Error: -sp was not specified\n");
      exit(0);
    }
    if (startNode + spanNodes - 1 > nodes) {
      print2("?Error: (-sn) + (-sp) - 1 must be %ld or less\n", nodes);
      exit(0);
    }
    if (quantifierVars[0] != 0) {
      print2(
 "?Error: quantifiers are not allowed if a start or end node is specified\n");
      exit(0);
    }
    if (startNode > 0) loopVar[loopDepth] = startNode - 1;
    if (spanNodes > 0) enNode = startNode + spanNodes - 1;
  }
  if (secondStartNode > 0 || secondSpanNodes > 0) {
    if (startNode == 0) {
      print2("?Error: -sn must be specified to use -ssn and -ssp\n");
      exit(0);
    }
    if (spanNodes != 1 && (secondStartNode != 1 || secondSpanNodes != nodes)) {
      print2(
"?Error: -sp must be 1 to use anything other than -ssn 1 and -ssp %ld\n",
          nodes);
      exit(0);
    }
    if (secondStartNode < 1 || secondStartNode > nodes) {
      print2("?Error: -ssn node must be from 1 and %ld\n", nodes);
      exit(0);
    }
    if (secondSpanNodes == 0) {
      print2("?Error: -ssp was not specified\n");
      exit(0);
    }
    if (secondStartNode + secondSpanNodes - 1 > nodes) {
      print2("?Error: (-ssn) + (-ssp) - 1 must be %ld or less\n", nodes);
      exit(0);
    }
    if (secondSpanNodes > 0)
      secondEnNode = secondStartNode + secondSpanNodes - 1;
  }
  /* end lattice2gperes7.c */

  while (1) {


    /* lattice2gperes7.c */
    if (startNode > 0) {
      if (loopDepth == 0 && loopVar[loopDepth] < nodes &&
          (loopVar[loopDepth] < enNode)) {
        print2("Processing node %ld of %ld...\n",
            loopVar[loopDepth] + 1, nodes);
      }
      if (secondStartNode > 0) {
        if (loopDepth == 1 && loopVar[loopDepth] < nodes &&
            (loopVar[loopDepth] < secondEnNode)) {
          print2("Processing second-level node %ld of %ld...\n",
              loopVar[loopDepth] + 1, nodes);
        }
      }
    }
    /* end lattice2gperes7.c */


    if (loopVar[loopDepth] < nodes

      /* lattice2gperes7.c */
      && (loopDepth != 0 || loopVar[loopDepth] < enNode)
      && (loopDepth != 1 || loopVar[loopDepth] < secondEnNode)
      /* end lattice2gperes7.c */

        ) { /* Loop not exhausted */
      /* Evaluate any hypotheses with less than current # variables */
      e = TRUE_CONST;
      for (i = 0; i < hypotheses; i++) {
        /* If the current variable# is > largest hypothesis variable,
           the hypothesis has been previously evaluated so we skip it */
        if (loopDepth > maxHypVar[i]) continue;
        /* Substitute lattice points for current variable in the
           hypothesis */
#if defined(PEVAL)
        /******* Partial evaluation speedup *******/
        tmplen = hypLenP[i][loopDepth];
        tmptrialeq1 = trialHypListP[i][loopDepth + 1];

        /* If a previous partial evaluation reduced the hypothesis
           to length 1 (i.e. true or false), we're done */
        if (tmplen == 1) {
          e = (trialHypListP[i][loopDepth])[0];
          /* Move down the length and the first character for next depth */
          hypLenP[i][loopDepth + 1] = 1;
          tmptrialeq1[0] = e;
          tmptrialeq1[1] = 0; /* End of string (for debugging) */
          if (e != TRUE_CONST) break; /* Out of i loop */
          continue;  /* On to next hypothesis */
        }

        tmpuav1 = unassignedHypVarsP[i][loopDepth + 1];
        tmpuav = unassignedHypVarsP[i][loopDepth];
        tmptrialeq = trialHypListP[i][loopDepth];
        tmploopv = loopVar[loopDepth];
        tmpvarord = varOrder[loopDepth];

        for (p = 0; p < tmplen; p++) {
          /* (If there are no variables at all, varOrder[0] will be 0
             i.e. end of string so we're still OK) */
          if (tmpuav[p] == 'y' && tmptrialeq[p] == tmpvarord) {
            tmptrialeq1[p] = nodeNames[tmploopv];
            tmpuav1[p] = 'n';
          } else {
            tmptrialeq1[p] = tmptrialeq[p];
            tmpuav1[p] = tmpuav[p];
          }
        }
        /* Assign end-of-string */
        tmptrialeq1[tmplen] = 0;
        tmpuav1[tmplen] = 0;
        hypLenP[i][loopDepth + 1] = tmplen;
#else
        for (p = 0; p < hypLen[i]; p++) {
          /* (If there are no variables at all, varOrder[0] will be 0
             i.e. end of string so we're still OK) */
          if ((polHypList[i])[p] == varOrder[loopDepth]) {
            (trialHypList[i])[p] = nodeNames[loopVar[loopDepth]];
          }
        }
#endif
        if (maxHypVar[i] == loopDepth
            /* Special case: make sure we don't skip hypotheses
               with constants only, using the following OR condition: */
            || (maxHypVar[i] < 0 && loopDepth == 0) /* For hyp w/ no vars */
            ) {
#if defined(PEVAL)
          e = eval(tmptrialeq1, tmplen);
#else
          e = eval(trialHypList[i], hypLen[i]);
#endif
          if (e != (wideChar)TRUE_CONST) break; /* Out of i loop */
#if defined(PEVAL)
        } else {
          /* loopDepth < maxHypVar[i] */
          /* Do a partial evaluation using variables assigned so far
             to reduce the length of the equation. */
          partialEval(tmptrialeq1, tmpuav1,
              &(hypLenP[i][loopDepth + 1]));
          /* If the evaluation reduced it to length 1, we're done */
          if (hypLenP[i][loopDepth + 1] == 1) {
            e = (trialHypListP[i][loopDepth + 1])[0];
            if (e != TRUE_CONST) break; /* Out of i loop */
          }
#else
#endif
        }
      } /* Next i */
      /* Skip deeper iterations if hypothesis is false */
      if (e == (wideChar)FALSE_CONST) goto nextIter;  /* A hypothesis
                                             failed; next iteration */
      if (e != (wideChar)TRUE_CONST) bug(240);
#if defined(PEVAL)
      if (loopDepth <= maxDepth) {
        /* Substitute lattice points for current variable in the conclusion */
        tmplen = conclusionLenP[loopDepth];
        tmpuav = unassignedConclVarsP[loopDepth];
        tmpuav1 = unassignedConclVarsP[loopDepth + 1];
        tmptrialeq = trialConclusionP[loopDepth];
        tmptrialeq1 = trialConclusionP[loopDepth + 1];
        tmploopv = loopVar[loopDepth];
        tmpvarord = varOrder[loopDepth];
        /******* Partial evaluation speedup *******/
        for (p = 0; p < tmplen; p++) {
          /* (If there are no variables at all, varOrder[0] will be 0
             i.e. end of string so we're still OK) */
          if (tmpuav[p] == 'y' && tmptrialeq[p] == tmpvarord) {
            tmptrialeq1[p] = nodeNames[tmploopv];
            tmpuav1[p] = 'n';
          } else {
            tmptrialeq1[p] = tmptrialeq[p];
            tmpuav1[p] = tmpuav[p];
          }
        }
        /* Assign end-of-string */
        tmptrialeq1[tmplen] = 0;
        tmpuav1[tmplen] = 0;
        conclusionLenP[loopDepth + 1] = tmplen;
      }
#else
      if (maxConclusionVar >= loopDepth) {
        /* Substitute lattice points for current variable in the conclusion */
        for (p = 0; p < conclusionLen; p++) {
          if (polConclusion[p] == varOrder[loopDepth]) {
            trialConclusion[p] = nodeNames[loopVar[loopDepth]];
          }
        }
      }
#endif
#if defined(PEVAL)
/* Adjust FUDGE_PARAMETER >= 0 for best speedup */
/* Note: for debugging, FUDGE_PARAMETER can be set to -1.  If average
   conclusion length does not always reduce to 1 then there is a bug. */
#define FUDGE_PARAMETER 0
      if (loopDepth < maxDepth - FUDGE_PARAMETER) {
        /* Do a partial evaluation using variables assigned so far
           to reduce the length of the equation. */
/*D*/if(0)printf("b%ld %ld %s %s\n",loopDepth,maxDepth,
/*D*/  printableString(tmptrialeq1),tmpuav1);
        partialEval(tmptrialeq1, tmpuav1,
            &(conclusionLenP[loopDepth + 1]));
/*D*/if(0)printf("a%ld %ld %s %s\n",loopDepth,maxDepth,
/*D*/  printableString(tmptrialeq1),tmpuav1);
      }
      /* Make iteration deeper if not deepest level and the partial
         evaluation still has expression length > 1 */
      if (loopDepth < maxDepth && (conclusionLenP[loopDepth + 1] > 1
          /* 5/18/04 nm If there are hypotheses whose variables haven't
             yet been totally assigned, one of them may still evaluate to
             false.  Thus even if the conclusion has been totally
             evaluated (length 1) we don't want to use it as the final
             result until we know what all the hypotheses evaluate to. */
          || hypotheses > 0)) {
#else
      /* Make iteration deeper unless deepest level */
      if (loopDepth < maxDepth) {
#endif
        loopDepth++;
        loopVar[loopDepth] = 0; /* Init var for next deeper level */
/* lattice2gperes7.c */
        if (secondStartNode > 0) {
          if (loopDepth == 1) {
            loopVar[loopDepth] = secondStartNode - 1;
          }
        }
/* end of lattice2gperes7.c */
        continue; /* to next interation of outermost "while (1)" loop */
      } else { /* loopDepth == maxDepth (or special case: loopDepth = 0
          and maxDepth = -1 if both hyp's & conclusion are all constants) */
#if defined(PEVAL)
        /* We're at the maximum variable depth, or partial evaluation
           reduced length to 1; get or evaluate conclusion */
        if (conclusionLenP[loopDepth + 1] == 1) {
          e = (trialConclusionP[loopDepth + 1])[0];
        } else {
          e = eval(trialConclusionP[loopDepth + 1], conclusionLenP[loopDepth]);
        }
        if (totB < LONG_MAX - conclusionLen) { /* Don't add if overflow - in
              this case final statistic will be less accurate, but that isn't
              critical since it is for info only */
          totA = totA + conclusionLenP[loopDepth + 1];
          totB = totB + conclusionLen;
          totC++;
        }
#else
        /* We're at the maximum variable depth; evaluate conclusion */
        e = eval(trialConclusion, conclusionLen);
#endif
        if (e != TRUE_CONST) {
          if (e != FALSE_CONST) bug(241);
          if (quantifierVars[0] != 0) {
            /* This is a quantified formula */
            /* See if this is a real failure, or whether we have more trials
               left for any existentially quantified variable */
            /* Find the last 'exists', if any, that still has not exhausted
               its variable assignment.  If there is one, it's not a real
               failure yet, but we will increment its variable assignment
               and try again. */
            for (i = maxDepth; i >= 0; i--) {
              if (quantifierTypes[i] == EXISTS_OPER && loopVar[i] < nodes - 1) {
                /* This is not a real failure yet as we still have more
                   trials left for this existential variable */
                /* Increment the variable and point the loop depth to
                   it to try again */
                loopDepth = i;
                loopVar[loopDepth]++;
                goto continue_;
              }
            }
            /* If it gets here, we've exhausted any 'exists' so it is
               a real failure; let normal (propositional) code proceed */
          }

          /* Conclusion is false */
          atLeastOneFailure = 1;
#if defined(PEVAL)
          /* Here we make the assignments to the real (not partially
             evaluated) hypotheses and conclusion for use by failure
             and visit displays */
          /* (6/18/01) When an early evaluation succeeds, loopDepth may be
             less than maxDepth (see
             "if (loopDepth < maxDepth && conclusionLenP[loopDepth + 1] > 1)"
             above; we're in the "else" part here).  An early evaluation
             succeeds when the conclusionLenP is 1.  In this case, variables
             deeper than loopDepth (up to maxDepth) are undefined and
             arbitrary.  So, we just make them the first node, the one
             that would be hit when the non-PEVAL algorithm runs, so the
             output will be consistent ("early evaluation case" below). */
          for (i = 0; i <= maxDepth; i++) {
            if (i > loopDepth) {
              /* Since the early evaluation succeeded, give the user some
                 information that may be helpful for further manual analysis
                 of the failure (this message may be commented out if it
                 becomes annoying). (6/18/01) */
              print2("Note: The failure is independent of variable %c.\n",
                  varOrder[i]);
            }
            for (j = 0; j < hypotheses; j++) {
              for (p = 0; p < hypLen[j]; p++) {
                /* (If there are no variables at all, varOrder[0] will be 0
                   i.e. end of string so we're still OK) */
                if ((polHypList[j])[p] == varOrder[i]) {
                  if (i <= loopDepth) { /* Normal case */
                    /* The loopVar has the node where the failure occurred */
                    (trialHypList[j])[p] = nodeNames[loopVar[i]];
                  } else { /* Early evaluation case (6/18/01) */
                    /* The loopVar has a meaningless node; set to 1st node */
                    (trialHypList[j])[p] = nodeNames[0];
                  }
                }
              }
            }
            for (p = 0; p < conclusionLen; p++) {
              if (polConclusion[p] == varOrder[i]) {
                if (i <= loopDepth) { /* Normal case */
                  /* The loopVar has the node where the failure occurred */
                  trialConclusion[p] = nodeNames[loopVar[i]];
                } else { /* Early evaluation case (6/18/01) */
                  /* The loopVar has a meaningless node; set to 1st node */
                  trialConclusion[p] = nodeNames[0];
                }
              }
            }
          } /* next i */
#else
#endif


          if (showVisits) {

            /* Show the failing assignment */
            print2("\n");
            print2("Failing variable assignment:\n");
            print2("  Variable   Node   Atom   Orig Atom\n");
            print2("  --------   ----   ----   ---------\n");
            for (i = 0; i <= maxDepth; i++) {
              if (maxDepth >= strlen(varOrder)) bug(998);
              let(&tmpStr2, chr(varOrder[i]));
              j = loopVar[i];
              let(&tmpStr3, printableString(wideString(1, nodeNames[j])));
              k = nodeToAtom(j + 1);
              let(&tmpStr4, printableAtomName(k));
              let(&tmpStr5, printableAtomName(atomReverseMap[k]));
              let(&tmpStr2, cat(left("     ", 5 - strlen(tmpStr2)),
                  tmpStr2, NULL));
              let(&tmpStr3, cat(left("        ", 8 - strlen(tmpStr3)),
                  tmpStr3, NULL));
              let(&tmpStr4, cat(left("        ", 8 - strlen(tmpStr4)),
                  tmpStr4, NULL));
              let(&tmpStr5, cat(left("          ", 10 - strlen(tmpStr5)),
                  tmpStr5, NULL));
              print2("%s %s %s %s\n", tmpStr2, tmpStr3, tmpStr4, tmpStr5,
                  (j > atoms + 1 && k > 0) ? "(co-atom)" : "" );
            }
            print2("\n");

            /* Show details of lattice failure evaluation (debugging mode) */
            print2("Details of lattice evaluation at failure:\n");
            visitFlag = 1;
            wideLet(&visitList, wideNullString);
                /* Initialize (redundant but just in case) */
            for (i = 0; i < hypotheses; i++) {
              print2("Hypothesis %ld\n", i + 1);
              /*e = eval(trialHypList[i]);*/ /* bad - doesn't show all nodes */
              /* Use unabbreviated version to see detailed visits */
              wideLet(&tmpWide, wideNullString);
              tmpWide = wideUnabbreviate(trialHypList[i]);
              e = eval(tmpWide, wideLen(tmpWide));
              let(&tmpStr, "");

            } /* Next i */
            print2("Conclusion\n");

            /*e = eval(trialConclusion);*/ /* bad - doesn't show all nodes */
            /* Use unabbreviated version to see detailed visits */
            wideLet(&tmpWide, wideNullString);
            tmpWide = wideUnabbreviate(trialConclusion);
            e = eval(tmpWide, wideLen(tmpWide));
            wideLet(&tmpWide, wideNullString);

            /* Show nodes not visited (useful for identifying redundant
               lattice points) */
            let(&tmpStr2, "");
            for (i = 0; i < wideLen(nodeNames); i++) {
              wideLet(&tmpWide, wideString(1, nodeNames[i]));
              if (!wideChrInStr(1, visitList, nodeNames[i])) {
                let(&tmpStr2, cat(tmpStr2, " ", printableString(tmpWide),
                    NULL));
              }
            }
            print2("\n");
            print2("Nodes not visited: %s\n", tmpStr2);

            /* For Greechie diagrams: show atoms not visited (useful for
               indentifying redundant atoms) */
            wideLet(&tmpWide, wideNullString);
            /* Construct a visited list for atoms */
            for (i = 0; i < wideLen(nodeNames); i++) {
              if (wideChrInStr(1, visitList, nodeNames[i])) {
                j = nodeToAtom(i + 1);
                if (j > 0) {
                  if (!wideChrInStr(1, tmpWide, j)) {
                    wideLet(&tmpWide,
                        wideCat(tmpWide, wideString(1, j), NULL));
                  }
                }
              }
            }
            let(&tmpStr2, "");
            let(&tmpStr3, "");
            for (j = 1; j <= atoms; j++) {
              if (!wideChrInStr(1, tmpWide, j)) {
                let(&tmpStr2, cat(tmpStr2, " ",
                    printableAtomName(j), NULL));  /* Internal remapped name */
                let(&tmpStr3, cat(tmpStr3, " ",
                    printableAtomName(atomReverseMap[j]), NULL)); /* Orig. */
              }
            }
            print2("Greechie lattice atoms not visited: %s\n", tmpStr2);
            if (strcmp(tmpStr2, tmpStr3))
              print2("Original lattice atoms not visited: %s\n", tmpStr3);
            let(&tmpStr2, "");
            let(&tmpStr3, "");
            let(&tmpStr4, "");
            let(&tmpStr5, "");
            /* This does not include internal nodes in blocks. */
            for (i = 1; i <= blocks; i++) {
              n = 0; /* Block visits */
              for (j = 1; j <= blockSize[i]; j++) {
                if (wideChrInStr(1, tmpWide, block[i][j])) {
                  n++;  /* Block is visited */
                }
              }
              if (n < 2) { /* Block has 0 or 1 visits */
                if (n < 1) { /* Block has 0 visits */
                  let(&tmpStr2, cat(tmpStr2, " ", NULL));
                  let(&tmpStr3, cat(tmpStr3, " ", NULL));
                  for (j = 1; j <= blockSize[i]; j++) {
                    let(&tmpStr2, cat(tmpStr2,
                        printableAtomName(block[i][j]), NULL));
                    let(&tmpStr3, cat(tmpStr3,
                        printableAtomName(atomReverseMap[block[i][j]]),
                        NULL));
                  }
                }
                let(&tmpStr4, cat(tmpStr4, " ", NULL));
                let(&tmpStr5, cat(tmpStr5, " ", NULL));
                for (j = 1; j <= blockSize[i]; j++) {
                  let(&tmpStr4, cat(tmpStr4,
                      printableAtomName(block[i][j]), NULL));
                  let(&tmpStr5, cat(tmpStr5,
                      printableAtomName(atomReverseMap[block[i][j]]),
                      NULL));
                }
              }
            }
            print2("Greechie blocks with 0 visits:%s\n", tmpStr2);
            if (strcmp(tmpStr2, tmpStr3))
              print2("Original blocks with 0 visits:%s\n", tmpStr3);
            print2("Greechie blocks with 0 or 1 visits:%s\n", tmpStr4);
            if (strcmp(tmpStr4, tmpStr5))
              print2("Original blocks with 0 or 1 visits:%s\n", tmpStr5);
            for (i = 1; i <= blocks; i++) {
              if (blockSize[i] > 3) {
                print2(
         "Warning: internal nodes for blocks with 4 or more atoms were not\n");
                print2("taken into account.\n");
                break;
              }
            }

            visitFlag = 0;
            wideLet(&visitList, wideNullString); /* Deallocate */
          } /* if (showVisits) */

          /* Construct failing assignment info string */
          let(&failingAssignment, ""); /* Clear any earlier failure */
          for (i = 0; i < hypotheses; i++) {
            if (i > 0)
              let(&failingAssignment, cat(failingAssignment, " & ", NULL));
            wideLet(&tmpWide, wideNullString);
            tmpWide = wideFromPolish(trialHypList[i]);
            let(&fromPol, printableString(tmpWide));
            /* Strip leading and trailing parenths */
            if (fromPol[0] == '(')
              let(&fromPol, seg(fromPol, 2, strlen(fromPol) - 1));
            let(&failingAssignment, cat(failingAssignment, fromPol,
                NULL));
          }
          if (hypotheses > 0)
            let(&failingAssignment, cat(failingAssignment, " => ", NULL));
          wideLet(&tmpWide, wideNullString);
          tmpWide = wideFromPolish(trialConclusion);
          let(&fromPol, printableString(tmpWide));
          /* Strip leading and trailing parenths */
          if (fromPol[0] == '(')
            let(&fromPol, seg(fromPol, 2, strlen(fromPol) - 1));
          let(&failingAssignment, cat(failingAssignment, fromPol,
              NULL));

          /* Normal (non-debugging) operation:  exit on first failure */
          if (!showAllFailures) goto done; /* Failed */

          /* Debugging mode: print the failure and try for another one */
          print2("FAILED %s at %s\n", latticeName, failingAssignment);

        } else { /* e == TRUE_CONST) */

          if (quantifierVars[0] != 0) {
            /* This is a quantified formula */
            /* See if this is a real pass, or whether we have more trials
               left for any universally quantified variable */
            /* Find the last 'forall', if any, that still has not exhausted
               its variable assignment.  If there is one, it's not a real
               pass yet, but we will increment its variable assignment
               and try again. */
            for (i = maxDepth; i >= 0; i--) {
              if (quantifierTypes[i] == FORALL_OPER && loopVar[i] < nodes - 1) {
                /* This is not a real pass yet as we still have more
                   trials left for this universal variable */
                /* Increment the variable and point the loop depth to
                   it to try again */
                loopDepth = i;
                loopVar[loopDepth]++;
                goto continue_;
              }
            }
            /* If it gets here, we've exhausted any 'for all' so it is
               a real pass */
            goto done;
          }

        } /* end if (e != TRUE_CONST) */
      } /* end of loopDepth >= maxDepth case */
    } else { /* loopVar[loopDepth] >= nodes) - loop exhausted */
      /* End of inner loop; pop up one level */
      loopDepth--;
      if (loopDepth < 0) break; /* Completely done - out of while loop */
    } /* end if (loopVar[loopDepth] < nodes) */
    /* Increment the loop variable */
   nextIter:
    loopVar[loopDepth]++;
   continue_:
    continue;
  } /* while (1) */
 done:
  if (atLeastOneFailure) {
    e = FALSE_CONST;
  } else {
    e = TRUE_CONST;
  }
#if defined(PEVAL)
  if (!oneLineOutput) {
    if (totC > 0) {
      print2(
    "Partial evaluations reduced average conclusion from %ld to %ld symbols.\n",
          totB / totC, totA / totC);
    } else {
      /* 5/18/04 nm If at least one hypothesis fails for every node assignment,
         the conclusion will never be evaluated.  We can't print the average
         above because we'd get a divide-by-zero error. */
      print2("Partial evaluations skipped the conclusion entirely (good).\n");
    }
  }
  for (i = 0; i <= maxDepth; i++) {  /* Deallocate strings */
    for (j = 0; j < hypotheses; j++) {
      wideLet(&(trialHypListP[j][i]), wideNullString);
      let(&(unassignedHypVarsP[j][i]), "");
    }
    wideLet(&(trialConclusionP[i]), wideNullString);
    let(&(unassignedConclVarsP[i]), "");
  }
#else
#endif
  wideLet(&trialConclusion, wideNullString); /* Deallocate string */
  let(&fromPol, ""); /* Deallocate string */
  let(&tmpStr, ""); /* Deallocate string */
  wideLet(&tmpWide, wideNullString); /* Deallocate string */
  let(&tmpStr2, ""); /* Deallocate string */
  let(&varOrder, ""); /* Deallocate string */
  for (i = 0; i < hypotheses; i++) {
    wideLet(&(trialHypList[i]), wideNullString);  /* Deallocate string */
  }
  let(&tmpStr3, ""); /* Deallocate string */
  let(&tmpStr4, ""); /* Deallocate string */
  let(&tmpStr5, ""); /* Deallocate string */
  return e;
} /* test() */


/* Converts all operators to v,^,- */
/* The caller must deallocate the result */
wideVstring wideUnabbreviate(wideVstring eqn)
{
  long i;
  long sblen1, sblen2;
  wideVstring subEqn1 = wideNullString;
  wideVstring subEqn2 = wideNullString;
  wideVstring newSubEqn = wideNullString;
  wideVstring subform = wideNullString;
  wideVstring eqn1 = wideNullString;
  wideLet(&eqn1, eqn); /* In case temp allocation passed in */
  /* Note: don't precompute wideLen(eqn1), since eqn1 grows */
  for (i = 1; i <= wideLen(eqn1); i++) {
    if (opMap[(wideChar)(eqn1[i - 1])] < 127) {
      /* It's a binary operation - unabbreviate it */
      subEqn1 = wideSubformula(wideRight(eqn1, i + 1));
      sblen1 = wideLen(subEqn1);
      subEqn2 = wideSubformula(wideRight(eqn1, i + 1 + sblen1));
      sblen2 = wideLen(subEqn2);
      switch ((wideChar)(eqn1[i - 1])) {
        /* I'm not sure whether it's helpful to do < & [ */
        case (wideChar)'>': /* greater than or equal:  x>y is y<x */
        case (wideChar)'<': /* less than or equal:  x<y is (xvy)=y */
          /*
          wideLet(&newSubEqn, wideCat(wide("=v"), subEqn1, subEqn2, subEqn2,
              NULL));
          break;
          */
        case (wideChar)'[': /* commutes:  x[y is x=((x^y)v(x^-y)) */
          /*
          wideLet(&newSubEqn, wideCat(wide("="), subEqn1, wide("v^"), subEqn1,
              subEqn2, wide("^"), subEqn1, wide("-"), subEqn2, NULL));
          break;
          */
        /* Primitive and metalogical connectives are not expanded */
        case (wideChar)'v':
        case (wideChar)'^':
        /*case (wideChar)'-':*/
                       /* Unary - shouldn't happen; let bugtrap catch it */
        case (wideChar)'=':
        /*case (wideChar)'~':*/
                       /* Unary - shouldn't happen; let bugtrap catch it */
        case (wideChar)'&': /* Metalogical AND */
        case (wideChar)'V': /* Metalogical OR */
        case (wideChar)'}': /* Metalogical implies */
        case (wideChar)':': /* Metalogical biconditional */
          /* This assignment does not expand the binary operation */
          wideLet(&newSubEqn, wideCat(wideMid(eqn1, i, 1), subEqn1, subEqn2,
              NULL));
          break;
        case (wideChar)'#': /* # = biimplication: ((x^y)v(-x^-y))*/
          wideLet(&newSubEqn, wideCat(wide("v^"), subEqn1, subEqn2, wide("^-"),
              subEqn1, wide("-"), subEqn2, NULL));
          break;
        case (wideChar)'O': /* O = ->0 = classical arrow: (-xvy) */
          wideLet(&newSubEqn, wideCat(wide("v-"), subEqn1, subEqn2, NULL));
          break;
        case (wideChar)'I': /* I = ->1 = Sasaki arrow: (-xv(x^y)) */
          wideLet(&newSubEqn, wideCat(wide("v-"), subEqn1, wide("^"), subEqn1,
              subEqn2, NULL));
          break;
        case (wideChar)'2': /* 2 = ->2 = Dishkant arrow: (yv(-x^-y)) */
          wideLet(&newSubEqn, wideCat(wide("v"), subEqn2, wide("^-"), subEqn1,
              wide("-"), subEqn2, NULL));
          break;
        case (wideChar)'3':
                  /* 3 = ->3 = Kalmbach arrow: (((-x^y)v(-x^-y))v(x^(-xvy))) */
          wideLet(&newSubEqn, wideCat(wide("vv^-"), subEqn1, subEqn2,
              wide("^-"), subEqn1, wide("-"), subEqn2, wide("^"), subEqn1,
              wide("v-"), subEqn1, subEqn2, NULL));
          break;
        case (wideChar)'4':
                 /* 4 = ->4 = non-tollens arrow: (((x^y)v(-x^y))v((-xvy)^-y))*/
          wideLet(&newSubEqn, wideCat(wide("vv^"), subEqn1, subEqn2,
              wide("^-"), subEqn1, subEqn2,
              wide("^v-"), subEqn1, subEqn2, wide("-"), subEqn2, NULL));
          break;
        case (wideChar)'5':
                      /* 5 = ->5 = relevance arrow: (((x^y)v(-x^y))v(-x^-y)) */
          wideLet(&newSubEqn, wideCat(wide("vv^"), subEqn1, subEqn2,
              wide("^-"), subEqn1, subEqn2,
              wide("^-"), subEqn1, wide("-"), subEqn2, NULL));
          break;
        default:
          bug(5);
      } /* end switch */
      wideLet(&eqn1, wideCat(wideLeft(eqn1, i - 1), newSubEqn,
          wideRight(eqn1, i + sblen1 + sblen2 + 1), NULL));
      wideLet(&subEqn1, wideNullString); /* Deallocate subformula() call */
      wideLet(&subEqn2, wideNullString); /* Deallocate subformula() call */
    } /* if (opMap[eqn1[i]] < 127) */
  } /* next i */
  wideLet(&newSubEqn, wideNullString); /* Deallocate */
  wideLet(&subform, wideNullString); /* Deallocate */
  return eqn1;
} /* wideUnabbreviate */

/* Converts all operators to v,^,- */
/* The caller must deallocate the result */
vstring unabbreviate(vstring eqn)
{
  long l, i;
  vstring sout = "";
  wideVstring wsout;
  unsigned char c;
  wsout = wideUnabbreviate(wide(eqn));
  l = wideLen(wsout);
  let(&sout, space(l));
  for (i = 0; i < l; i++) {
    /* Should never be called with non-ASCII */
    if (wsout[i] > /*255*/ 127) bug(250); /* 127 = extra conservative */
    c = wsout[i];
    sout[i] = c;
  }
  wideLet(&wsout, wideNullString);
  return sout;
} /* unabbreviate */

/* Returns a comma-separated list of all subformulas in an
   equation */
/* The caller must deallocate the result */
vstring subformulaList(vstring eqn)
{
  long i, j, k, p;
  long length;
  vstring subform = "";
  vstring list = "";
  vstring eqn1 = "";
  vstring e = "";
  vstring unabbrList = "";
  let(&eqn1, eqn); /* In case temp allocation passed in */
  length = strlen(eqn1);
  for (i = 1; i <= length; i++) {
    let(&subform, ""); subform = subformula(right(eqn1, i));
    /* Ignore negated subformulas to make list cleaner */
    while (subform[0] == NEG_OPER || subform[0] == NOT_OPER)
      let(&subform, right(subform, 2));
    /* If the subformula isn't in the list, add it */
    if (lookup(subform, list) == 0
        /* Also look at unabbreviated list, so we won't have abbreviated
           and unabbreviated duplicates (this assume abbreviated form of
           expression appears first in eqn1 - see findCommutingPairs()
           function) */
        && lookup(subform, unabbrList) == 0
        ) {
      if (list[0] == 0) {
        let(&list, subform);
      } else {
        /*let(&list, cat(list, ",", subform, NULL));*/
        /* Figure out where it should go - shortest first */
        j = numEntries(list);
        for (k = 1; k <= j; k++) {
          let(&e, entry(k, list));
          if (strlen(e) > strlen(subform) ||
              (strlen(e) == strlen(subform) && strcmp(e, subform) > 0)) {
            /* A longer one found - put it before */
            p = entryPosition(k, list);
            let(&list, cat(left(list, p - 1), subform, ",", right(list, p),
                NULL));
            break;
          }
        } /* next k */
        if (k > j) {
          /* It's the biggest - put at end of list */
          let(&list, cat(list, ",", subform, NULL));
        }
      }

      /* Add to unabbreviated list */
      let(&e, "");
      e = unabbreviate(subform);
      if (unabbrList[0] == 0) {
        let(&unabbrList, e);
      } else {
        let(&unabbrList, cat(unabbrList, ",", e, NULL));
      }

    }
  }
  let(&subform, "");
  let(&eqn1, "");
  let(&e, "");
  return list;
} /* subformulaList() */



/* Returns the char value of the nodeName character that the
   trial equation evaluates to */
wideChar eval(wideVstring trialEqn, long eqnLen)
{
  wideChar e;
  wideVstring subEqn1; /* Don't initialize here (for speedup) */
  wideVstring subEqn2; /* Don't initialize here (for speedup) */

  /* Speedup - use the fast version */
  if (e == e) {
    /* Put "visitFlag || 1" for verifying fastEval vs. ultraFastEval
       for debugging purposes */
    if (visitFlag) {
      /* This evaluation prints out the visits */
      e = fastEval(trialEqn, 0);
      /* This bugcheck makes sure that the two methods give the same
         result */
      if (e != ultraFastEval(trialEqn, eqnLen)) bug(111);
      return e;
    } else {
      return ultraFastEval(trialEqn, eqnLen);
    }
  }

  /* The code below is for the slower original algorithm and never
     gets run unless the speedup block above is commented out -
     but it should give the same results for debugging, except
     the "visitFlag" is not implemented */
  /* For speedup - initialize vstrings only if old algorithm is being run */
  subEqn1 = wideNullString;
  subEqn2 = wideNullString;
  if ((wideChar)(trialEqn[0]) == (wideChar)NEG_OPER) {
    wideLet(&subEqn1, wideRight(trialEqn, 2));
    /*
    e = lookupCompl(eval(subEqn1));
    */
    /* Speedup */
    e = negMap[eval(subEqn1, wideLen(subEqn1))];
  } else {
    if ((wideChar)(trialEqn[0]) == (wideChar)NOT_OPER) {
      /* Classical metalogical NOT */
      wideLet(&subEqn1, wideRight(trialEqn, 2));
      if (eval(subEqn1, wideLen(subEqn1)) == (wideChar)TRUE_CONST) {
        e = (wideChar)FALSE_CONST;
      } else {
        if (eval(subEqn1, wideLen(subEqn1)) == (wideChar)FALSE_CONST) {
          e = (wideChar)TRUE_CONST;
        } else {
          bug(200);
        }
      }
    } else {
      /*
      if (instr(1, ALL_BIN_CONNECTIVES, chr(trialEqn[0])) != 0) {
      */
      /* Speedup */
      if (opMap[(wideChar)(trialEqn[0])] < 127) {
        subEqn1 = wideSubformula(wideRight(trialEqn, 2));
        subEqn2 = wideSubformula(wideRight(trialEqn, wideLen(subEqn1) + 2));
        /*
        e = lookupBinOp(trialEqn[0], eval(subEqn1), eval(subEqn2));
        */
        /* Speedup */
        if (!wideChrInStr(1, wide(LOGIC_BIN_CONNECTIVES), trialEqn[0])) {
          e = binOpTable[(unsigned char)(opMap[(wideChar)(trialEqn[0])])]
             [nodeNameMap[eval(subEqn1, wideLen(subEqn1))]]
             [nodeNameMap[eval(subEqn2, wideLen(subEqn2))]];
        } else {
          e = binOpTable[(unsigned char)(opMap[(wideChar)(trialEqn[0])])]
             [eval(subEqn1, wideLen(subEqn1))]
             [eval(subEqn2, wideLen(subEqn2))];
        }
      } else {
        /* Must be a node */
        e = (wideChar)(trialEqn[0]);
      }
    }
  }
  wideLet(&subEqn1, wideNullString);  /* Deallocate vstring */
  wideLet(&subEqn2, wideNullString);  /* Deallocate vstring */
  return e;

} /* eval */


/* Returns the char value of the nodeName character that the
   trial equation evaluates to */
/* startChar = 0 is 1st char in string, 1 is 2nd, etc. */
wideChar fastEval(wideVstring trialEqn, long startChar)
{
  wideChar e;
  long i;
  wideVstring s1; /* Don't initialize for speedup */
  wideVstring s2; /* Don't initialize for speedup */

  if ((wideChar)(trialEqn[startChar]) == (wideChar)NEG_OPER) {
    e = negMap[fastEval(trialEqn, startChar + 1)];
  } else {
    if ((wideChar)(trialEqn[startChar]) == (wideChar)NOT_OPER) {
      e = fastEval(trialEqn, startChar + 1);
      if (e == (wideChar)TRUE_CONST) {
        e = (wideChar)FALSE_CONST;
      } else {
        if (e == (wideChar)FALSE_CONST) {
          e = (wideChar)TRUE_CONST;
        } else {
          bug(252);
        }
      }
    } else {
      if (opMap[trialEqn[startChar]] < 127) {
        i = wideSubformulaLen(trialEqn, startChar + 1);
        /* Don't use wide(LOGIC_BIN_CONNECTIVES) to prevent string stack ovf */
        if (!wideChrInStr(1, WIDE_LOGIC_BIN_CONNECTIVES,
            trialEqn[startChar])) {
          e = binOpTable[(unsigned char)(opMap[trialEqn[startChar]])]
             [nodeNameMap[fastEval(trialEqn, startChar + 1)]]
             [nodeNameMap[fastEval(trialEqn, startChar + i + 1)]];
        } else {
          e = binOpTable[(unsigned char)(opMap[trialEqn[startChar]])]
             [fastEval(trialEqn, startChar + 1)]
             [fastEval(trialEqn, startChar + i + 1)];
        }
      } else {
        /* Must be a node */
        e = (wideChar)(trialEqn[startChar]);
      }
    }
    if (visitFlag) {
      /* Show user details of failing lattice visit */
      s1 = wideSubformula(wideRight(trialEqn, startChar + 1));
      s2 = wideFromPolish(s1);
      if (wideChrInStr(1, wide(LOGIC_AND_RELATION_CONNECTIVES),
            trialEqn[startChar])) {
        /* Ignore final result (will be FALSE_CONST, which means "false"
           or TRUE_CONST for "true" in the case of hypothesis) */
        if (e != FALSE_CONST && e != TRUE_CONST) print2("%ld\n",(long)e);
        if (e != FALSE_CONST && e != TRUE_CONST) bug(201);
        if (e == FALSE_CONST) print2("(false) = %s\n", printableString(s2));
        if (e == TRUE_CONST) print2("(true) = %s\n", printableString(s2));
      } else {
        print2("%s = %s\n", printableString(wideString(1, e)),
            printableString(s2));
        wideLet(&visitList, wideCat(visitList, wideString(1, e), NULL));
      }
      wideLet(&s1, wideNullString); /* Deallocate */
      wideLet(&s2, wideNullString); /* Deallocate */
    }
  }
  return e;
}

/* Returns the char value of the nodeName character that the
   trial equation evaluates to */
/* This is faster than "fastEval" because it eliminates a
   recursive call */
wideChar ultraFastEval(wideVstring trialEqn, long eqnLen)
{
  wideChar stack[MAX_STACK2];
  wideChar e, e1;
  long i, stackPtr;

  /* For debugging - print the equation in Polish notation */
  /* print2("%s\n", trialEqn); */

  stackPtr = -1;

  for (i = eqnLen - 1; i >= 0; i--) {
    e = (wideChar)(trialEqn[i]);

    if (e == (wideChar)NEG_OPER) {
      /* Comment out bugcheck for speedup */
      /* Should never happen because of input expression syntax check */
      /* if (stackPtr < 0) bug(107); */
      stack[stackPtr] = negMap[stack[stackPtr]];
    } else {
      if (e == (wideChar)NOT_OPER) {
        if (stack[stackPtr] == (wideChar)TRUE_CONST) {
          stack[stackPtr] = (wideChar)FALSE_CONST;
        } else {
          if (stack[stackPtr] != (wideChar)FALSE_CONST) bug(251);
          stack[stackPtr] = (wideChar)TRUE_CONST;
        }
      } else {
        e1 = opMap[e];
        if (e1 < 127) {
          stackPtr--;
          /* Comment out bugcheck for speedup */
          /* Should never happen because of input expression syntax check */
          /* if (stackPtr < 0) bug(108); */
          /*
          stack[stackPtr] = binOpTable[opMap[e]]
             [nodeNameMap[stack[stackPtr + 1]]]
             [nodeNameMap[stack[stackPtr]]];
          */
          /* Speedup:  eliminate indirect subscript */
          stack[stackPtr] = ultraFastBinOpTable[e1]
             [stack[stackPtr + 1]]
             [stack[stackPtr]];
        } else {
          /* Must be a node */
          stackPtr++;
          /* Could comment out bugcheck for ~5% speedup - but would be dangerous
             if input expression too long - future: we could pre-check this */
          if (stackPtr >= MAX_STACK2) bug(109);
          stack[stackPtr] = e;
        }
      }
    }
  }
  /* Comment out bugcheck for speedup */
  /* Should never happen because of input expression syntax check */
  /* if (stackPtr) bug(110); */
  return (wideChar)(stack[0]);
} /* ultraFastEval */
#if defined(PEVAL)
/* Returns a partially evaluated equation in trialEqn based
   on variable assignments that are known */
/* Derived from "ultraFastEval" function above */
/* trialEqn has the starting eqn and returns the (shortened) partially
   evaluated eqn.
   unassignedVarFlags has 'y' if unassigned var, 'n' if node,
   'u' (unevaluated operator) otherwise.
   eqnLen has initial trialEqn length and returns final
   trialEqn length.  Returned unassignedVarFlags is usable by next call. */
void partialEval(wideVstring trialEqn, vstring unassignedVarFlags,
    long *eqnLen)
{
  wideChar stack[MAX_STACK];
  long stackSubexprLen[MAX_STACK]; /* Has unevaluated subexpr len for stack */
  long stackUnevalFlag[MAX_STACK]; /* Has uneval (=2) flags for stack */
  wideChar e, e1;
  long i, j, stackPtr, l1, l2;

  /* For debugging - print the equation in Polish notation */
  /* print2("%s\n", trialEqn); */

  stackPtr = -1;

  for (i = (*eqnLen) - 1; i >= 0; i--) {
    e = (wideChar)(trialEqn[i]);
/*D*/if(0 && i<10){
/*D*/printf("%ld %c ",i,e);for(j=stackPtr;j>=0;j--)printf("  %c",stack[j]);printf("\n");
/*D*/printf("%ld %c ",i,e);for(j=stackPtr;j>=0;j--)printf("%3ld",stackSubexprLen[j]);printf("\n");
/*D*/}

    if (e == (wideChar)NEG_OPER) {
      /* Comment out bugcheck for speedup */
      /* Should never happen because of input expression syntax check */
      /* if (stackPtr < 0) bug(307); */
      if (stackUnevalFlag[stackPtr] != 'n') {
        /* If the argument is an uneval subexpr, make the result an
           unevaluated subexpr */
        stackPtr++;
        stack[stackPtr] = e;
        stackUnevalFlag[stackPtr] = 'u'; /* uneval. expression */
        stackSubexprLen[stackPtr] = stackSubexprLen[stackPtr - 1] + 1;
      } else {
        /* Normal subexpression */
        stack[stackPtr] = negMap[stack[stackPtr]];
        stackUnevalFlag[stackPtr] = 'n'; /* assigned node */
        stackSubexprLen[stackPtr] = 1;
      }
      continue;
    }
    if (e == NOT_OPER) {
      if (stackUnevalFlag[stackPtr] != 'n') {
        /* If the argument is an uneval subexpr, make the result an
           unevaluated subexpr */
        stackPtr++;
        stack[stackPtr] = e;
        stackUnevalFlag[stackPtr] = 'u'; /* uneval. expression */
        stackSubexprLen[stackPtr] = stackSubexprLen[stackPtr - 1] + 1;
      } else {
        /* Normal subexpression */
        if (stack[stackPtr] == TRUE_CONST) {
          stack[stackPtr] = FALSE_CONST;
        } else {
          if (stack[stackPtr] != FALSE_CONST) bug(351);
          stack[stackPtr] = TRUE_CONST;
        }
        stackUnevalFlag[stackPtr] = 'n'; /* assigned node */
        stackSubexprLen[stackPtr] = 1;
      }
      continue;
    }
    e1 = opMap[e];
    if (e1 < 127) { /* It is a binary operator */
      l1 = stackSubexprLen[stackPtr];
      l2 = stackSubexprLen[stackPtr - l1];
      if (stackUnevalFlag[stackPtr] != 'n'
          || stackUnevalFlag[stackPtr - l1] != 'n') {
        /* If either argument is either an unassigned var or an
           unevaluated subexpr (containing an unassigned var), then
           we make the result an unevaluated subexpr */
        /* Handle special cases */
        if (stackUnevalFlag[stackPtr] == 'n') {
          if (l1 != 1) bug(313);
          if (stack[stackPtr] == '0') { /* 1st arg is 0 */
            if (e == (wideChar)'^') {
              /* Result is 0 */
              stackPtr = stackPtr - l1 - l2 + 1;
              stack[stackPtr] = '0';
              stackUnevalFlag[stackPtr] = 'n';
              stackSubexprLen[stackPtr] = 1;
              continue;
            }
            if (e == (wideChar)'v') {
              /* Result is expression - remove the 0 */
              stackPtr--;
              continue;
            }
            if (e == (wideChar)'I') {
              /* Result is 1 */
              stackPtr = stackPtr - l1 - l2 + 1;
              stack[stackPtr] = (wideChar)'1';
              stackUnevalFlag[stackPtr] = 'n';
              stackSubexprLen[stackPtr] = 1;
              continue;
            }
            if (e == (wideChar)'<') {
              /* Result is TRUE_CONST */
              stackPtr = stackPtr - l1 - l2 + 1;
              stack[stackPtr] = TRUE_CONST;
              stackUnevalFlag[stackPtr] = 'n';
              stackSubexprLen[stackPtr] = 1;
              continue;
            }
          }
          if (stack[stackPtr] == '1') { /* 1st arg is 1 */
            if (e == (wideChar)'v') {
              /* Result is 1 */
              stackPtr = stackPtr - l1 - l2 + 1;
              stack[stackPtr] = (wideChar)'1';
              stackUnevalFlag[stackPtr] = 'n';
              stackSubexprLen[stackPtr] = 1;
              continue;
            }
            if (e == (wideChar)'^') {
              /* Remove the 1 */
              stackPtr--;
              continue;
            }
            if (e == (wideChar)'I') {
              /* Result is expression - remove the 1 */
              stackPtr--;
              continue;
            }
          }
        }
        if (stackUnevalFlag[stackPtr - l1] == 'n') {
          if (l2 != 1) bug(314);
          if (stack[stackPtr - l1] == (wideChar)'0') { /* 2nd arg is 0 */
            if (e == (wideChar)'^') {
              /* Result is 0 */
              stackPtr = stackPtr - l1 - l2 + 1;
              stack[stackPtr] = (wideChar)'0';
              stackUnevalFlag[stackPtr] = 'n';
              stackSubexprLen[stackPtr] = 1;
              continue;
            }
            if (e == (wideChar)'v') {
              /* Remove the 0 */
              for (j = stackPtr - l1; j < stackPtr; j++) {
                stack[j] = stack[j + 1];
                stackUnevalFlag[j] = stackUnevalFlag[j + 1];
                stackSubexprLen[j] = stackSubexprLen[j + 1];
              }
              stackPtr--;
              continue;
            }
            if (e == (wideChar)'I') {
              /* Result is -expression */
              for (j = stackPtr - l1; j < stackPtr; j++) {
                stack[j] = stack[j + 1];
                stackUnevalFlag[j] = stackUnevalFlag[j + 1];
                stackSubexprLen[j] = stackSubexprLen[j + 1];
              }
              /*stackPtr = stackPtr;*/
              stack[stackPtr] = (wideChar)'-';
              stackUnevalFlag[stackPtr] = 'u';
              stackSubexprLen[stackPtr] = l1 + 1;
              continue;
            }
          }
          if (stack[stackPtr - l1] == (wideChar)'1') {  /* 2nd arg is 1 */
            if (e == (wideChar)'^') {
              /* Remove the 1 */
              for (j = stackPtr - l1; j < stackPtr; j++) {
                stack[j] = stack[j + 1];
                stackUnevalFlag[j] = stackUnevalFlag[j + 1];
                stackSubexprLen[j] = stackSubexprLen[j + 1];
              }
              stackPtr--;
              continue;
            }
            if (e == (wideChar)'v') {
              /* Result is 1 */
              stackPtr = stackPtr - l1 - l2 + 1;
              stack[stackPtr] = (wideChar)'1';
              stackUnevalFlag[stackPtr] = 'n';
              stackSubexprLen[stackPtr] = 1;
              continue;
            }
            if (e == (wideChar)'I') {
              /* Result is 1 */
              stackPtr = stackPtr - l1 - l2 + 1;
              stack[stackPtr] = (wideChar)'1';
              stackUnevalFlag[stackPtr] = 'n';
              stackSubexprLen[stackPtr] = 1;
              continue;
            }
            if (e == (wideChar)'<') {
              /* Result is TRUE_CONST */
              stackPtr = stackPtr - l1 - l2 + 1;
              stack[stackPtr] = (wideChar)TRUE_CONST;
              stackUnevalFlag[stackPtr] = 'n';
              stackSubexprLen[stackPtr] = 1;
              continue;
            }
          }
        }
        stackPtr++;
        stack[stackPtr] = e;
        stackUnevalFlag[stackPtr] = 'u'; /* "uneval. expression" */
        stackSubexprLen[stackPtr] = l1 + l2 + 1;
      } else {
        /* Normal subexpression */
        stackPtr--;
        /* Comment out bugcheck for speedup */
        /* Should never happen because of input expression syntax check */
        /* if (stackPtr < 0) bug(308); */
        /*
        stack[stackPtr] = binOpTable[opMap[e]]
           [nodeNameMap[stack[stackPtr + 1]]]
           [nodeNameMap[stack[stackPtr]]];
        */
        /* Speedup:  eliminate indirect subscript */
        stack[stackPtr] = ultraFastBinOpTable[e1]
           [stack[stackPtr + 1]]
           [stack[stackPtr]];
        stackUnevalFlag[stackPtr] = 'n'; /* assigned node */
        stackSubexprLen[stackPtr] = 1;
      }
      continue;
    }
    /* Must be a node, or an unassigned variable. */
    stackPtr++;
    /* Could comment out bugcheck for ~5% speedup - but would be dangerous
       if input expression too long - future: we could pre-check this */
    if (stackPtr >= MAX_STACK) bug(309);
    stack[stackPtr] = e;
    /* Put the unassigned variable flag in the stack */
    /* 'y' if unassigned var, 'n' if node */
    stackUnevalFlag[stackPtr] = unassignedVarFlags[i];
    /* Put the subexpression length in the stack */
    stackSubexprLen[stackPtr] = 1;
  } /* next i */
  /* Comment out bugcheck for speedup */
  /* Should never happen because of input expression syntax check */
  if (stackPtr < 0) bug(310);
/*D*/if (0 &&(*eqnLen) != stackPtr + 1) printf("b: %s %s\n",
/*D*/  printableString(trialEqn),unassignedVarFlags);
  /* Copy stack to new equation */
  for (i = 0; i <= stackPtr; i++) {
    trialEqn[stackPtr - i] = stack[i];
    unassignedVarFlags[stackPtr - i] = stackUnevalFlag[i];
  }
  trialEqn[stackPtr + 1] = 0; /* End of string - necessary? */
  unassignedVarFlags[stackPtr + 1] = 0; /* End of string - necessary? */
/*D*/if (0 &&(*eqnLen) != stackPtr + 1) printf("a: %s %s\n",
/*D*/ printableString(trialEqn),unassignedVarFlags);
  (*eqnLen) = stackPtr + 1; /* New partially eval'd eqn length */
  return;
} /* partialEval */


#else
#endif


/* Returns the shortest subformula from beginning of equation */
/* The caller must deallocate the result */
wideVstring wideSubformula(wideVstring eqn)
{
  wideVstring result = wideNullString;
  long i, p;
  wideLet(&result, eqn); /* In case temp allocation passed in */
  i = 0;
  p = 1;
  while (p > 0) {
    /*
    if (instr(1, ALL_BIN_CONNECTIVES, chr(result[i])) != 0) {
    */
    /* Speedup */
    if (opMap[(wideChar)(result[i])] < 127) {
      p++;
    } else {
      if ((wideChar)(result[i]) != (wideChar)NEG_OPER
          && (wideChar)(result[i]) != (wideChar)NOT_OPER)
        p--;  /* It is a node name or constant */
    }
    i++;
  }
  wideLet(&result, wideLeft(result, i));
  return result;
}


/* Returns the shortest subformula from beginning of equation */
/* The caller must deallocate the result */
vstring subformula(vstring eqn)
{
  vstring result = "";
  long i, p;
  let(&result, eqn); /* In case temp allocation passed in */
  i = 0;
  p = 1;
  while (p > 0) {
    /*
    if (instr(1, ALL_BIN_CONNECTIVES, chr(result[i])) != 0) {
    */
    /* Speedup */
    if (opMap[(wideChar)(result[i])] < 127) {
      p++;
    } else {
      if ((unsigned char)(result[i]) != NEG_OPER
          && (unsigned char)(result[i]) != NOT_OPER)
        p--;  /* It is a node name or constant */
    }
    i++;
  }
  let(&result, left(result, i));
  return result;
}


/* Returns the length of the shortest subformula from startChar */
long subformulaLen(vstring eqn, long startChar)
{
  long i, p;
  i = 0;
  p = 1;
  while (p > 0) {
    if (opMap[(wideChar)(eqn[startChar + i])] < 127) {
      p++;
    } else {
      if ((unsigned char)(eqn[startChar + i]) != NEG_OPER
          && (unsigned char)(eqn[startChar + i]) != NOT_OPER)
        p--; /* It is a node name or constant */
    }
    i++;
  }
  return i;
}


/* Returns the length of the shortest subformula from startChar */
long wideSubformulaLen(wideVstring eqn, long startChar)
{
  long i, p;
  i = 0;
  p = 1;
  while (p > 0) {
    if (opMap[eqn[startChar + i]] < 127) {
      p++;
    } else {
      if (eqn[startChar + i] != (wideChar)NEG_OPER
          && eqn[startChar + i] != (wideChar)NOT_OPER)
        p--; /* It is a node name or constant */
    }
    i++;
  }
  return i;
}


wideChar lookupCompl(wideChar arg) {
  /* abc... = node names; ABC.. = complemented node names */
  /*
  if (arg == '0') return '1';
  if (arg == '1') return '0';
  if (isupper(arg)) return tolower(arg);
  if (islower(arg)) return toupper(arg);
  bug(6);
  return 0;
  */
  /* Speedup */
  return negMap[arg];
}

wideChar lookupNot(wideChar arg) {
  /* Complement TRUE_CONST or FALSE_CONST */
  if (arg == TRUE_CONST) return FALSE_CONST;
  if (arg == FALSE_CONST) return TRUE_CONST;
  bug(225);
  return 0;
}

/* The input/output of lookupBinOp are actual nodes names. */
/* Except, for the case of metalogical true and false, the inputs must
   be the (meaningless) node names TRUE_CONST
   and FALSE_CONST.  The outputs are also these
   meaningless node names.  The nodeNames and nodeNameMap should not
   be used for these. */
wideChar lookupBinOp(wideChar operation, wideChar arg1,
    wideChar arg2) {
    /*
    ^ = conjunction
    v = disjunction
    # = biimplication: ((x^y)v(-x^-y))
    O = ->0 = classical arrow: (-xvy)
    I = ->1 = Sasaki arrow: (-xv(x^y))
    2 = ->2 = Dishkant arrow: (-yI-x)
    3 = ->3 = Kalmbach arrow: (((-x^y)v(-x^-y))v(x^(-xvy)))
    4 = ->4 = non-tollens arrow: (-y3-x)
    5 = ->5 = relevance arrow: (((x^y)v(-x^y))v(-x^-y))

    = = equals predicate - returns T or F
    < = less-than-or-equal predicate:  ((xvy)=y) - returns T or F
    [ = commutes predicate:  (x=((x^y)v(x^-y))) - returns T or F
    */
  wideChar result;
  switch (operation) {
    case (wideChar)'v':
      /* Speedup:  eliminate instr() w/ char map */
      /* the sup[][] table indexes are 0,1,... from node name
         via nodeNameMap.   The value of sup[][] is an actual
         node name. */
      if (1) return (sup[nodeNameMap[arg1]][nodeNameMap[arg2]])[0];
      break;
    case (wideChar)'^':
      result = lookupCompl(lookupBinOp('v', lookupCompl(arg1),
          lookupCompl(arg2)));
      break;
    case (wideChar)'#':
      result = lookupBinOp('v',
                lookupBinOp('^', arg1, arg2),
                lookupCompl(lookupBinOp('v', arg1, arg2)));
      break;
    case (wideChar)'O':
      result = lookupBinOp('v', lookupCompl(arg1), arg2);
      break;
    case (wideChar)'I':
      result = lookupBinOp('v', lookupCompl(arg1),
                lookupBinOp('^', arg1, arg2));
      break;
    case (wideChar)'2':
      result = lookupBinOp('I', lookupCompl(arg2), lookupCompl(arg1));
      break;
    case (wideChar)'3':
      result = lookupBinOp('v',
               lookupBinOp('v',
                 lookupBinOp('^', lookupCompl(arg1), arg2),
                 lookupBinOp('^', lookupCompl(arg1), lookupCompl(arg2))),
               lookupBinOp('^', arg1,
                 lookupBinOp('v', lookupCompl(arg1), arg2)));
      break;
    case (wideChar)'4':
      result = lookupBinOp('3', lookupCompl(arg2), lookupCompl(arg1));
      break;
    case (wideChar)'5':
      result = lookupBinOp('v',
               lookupBinOp('v',
                 lookupBinOp('^', arg1, arg2),
                 lookupBinOp('^', lookupCompl(arg1), arg2)),
               lookupBinOp('^', lookupCompl(arg1), lookupCompl(arg2)));
      break;

    case (wideChar)'=':
      if (arg1 == arg2) {
        result = TRUE_CONST;
      } else {
        result = FALSE_CONST;
      }
      break;
    case (wideChar)'<': /* Less than or equal to */
      result = lookupBinOp('=', lookupBinOp('v', arg1, arg2), arg2);
      break;
    case (wideChar)'>': /* Greater than or equal to */
      result = lookupBinOp('<', arg2, arg1);
      break;
    case (wideChar)'[': /* Commutes */
      result = lookupBinOp('=', arg1, lookupBinOp('v',
                 lookupBinOp('^', arg1, arg2),
                 lookupBinOp('^', arg1, lookupCompl(arg2))));
      break;
    case (wideChar)OR_OPER:
      /* Classical metalogic */
      if ((arg1 != TRUE_CONST
            && arg1 != FALSE_CONST)
          || (arg2 != TRUE_CONST
            && arg2 != FALSE_CONST))
        bug(231);
      if (arg1 == TRUE_CONST
          || arg2 == TRUE_CONST) {
        result = TRUE_CONST;
      } else {
        result = FALSE_CONST;
      }
      break;
    case (wideChar)AND_OPER:
      /* Classical metalogic */
      if ((arg1 != TRUE_CONST
            && arg1 != FALSE_CONST)
          || (arg2 != TRUE_CONST
            && arg2 != FALSE_CONST))
        bug(230);
      result = lookupNot(lookupBinOp(OR_OPER, lookupNot(arg1),
          lookupNot(arg2)));
      break;
    case (wideChar)IMPL_OPER:
      /* Classical metalogic */
      if ((arg1 != TRUE_CONST
            && arg1 != FALSE_CONST)
          || (arg2 != TRUE_CONST
            && arg2 != FALSE_CONST))
        bug(232);
      result = lookupBinOp(OR_OPER, lookupNot(arg1), arg2);
      break;
    case (wideChar)BI_OPER:
      /* Classical metalogic */
      if ((arg1 != TRUE_CONST
            && arg1 != FALSE_CONST)
          || (arg2 != TRUE_CONST
            && arg2 != FALSE_CONST))
        bug(233);
      result = lookupBinOp(OR_OPER,
                lookupBinOp(AND_OPER, arg1, arg2),
                lookupNot(lookupBinOp(OR_OPER, arg1, arg2)));
      break;
    default:
      result = 0;
      bug(7);
  } /* switch (operation) */

  /* Uncomment for debugging */
  /*
  print2("%s %s %s = %s\n", chr(arg1), chr(operation), chr(arg2),
      chr(result));
  */
  return result;
}


/* ***Note:  The caller must deallocate returned string! */
/* Convert normal to Polish notation */
/* recursiveCall should be 0 when calling from outside, and nonzero when
   toPolish calls itself recursively */
/* Since this error checks user's input arguments, error exits program with
   message rather than return an error value */
vstring toPolish(vstring equation)
{
 /* This function converts a theorem in parentheses notation to
    one in Polish notation */

  long i, j, k, eqnLen, subEqn1Len, subEqn2Len;
  char operation;
  vstring polEqn = "";
  vstring equation1 = "";
  vstring subEqn1 = "";
  vstring subEqn2 = "";
  vstring polSubEqn1 = "";
  vstring polSubEqn2 = "";
  vstring quantifiers = "";
  static long recursiveCall = 0;

  /* Make any tempAlloc of equation permanent */
  let(&equation1, equation);

  eqnLen = strlen(equation1);
  if (!recursiveCall) {

    /* Upon first entry, count parentheses for better user information */
    j = 0; k = 0;
    for (i = 0; i < eqnLen; i++) {
      if (equation1[i] == '(') j++;
      if (equation1[i] == ')') k++;
    }
    if (j != k) {
      print2("?Error: There are %ld left but %ld right parentheses in %s\n",
          j, k, equation1);
      exit(0);
    }

    /* Upon first entry, strip off quantifiers to leave only the
       wff part of a qwff in prenex normal form */
    for (i = eqnLen - 1; i >= -1; i--) {
      if (i == -1) break;
      if (strchr(QUANTIFIER_CONNECTIVES, equation1[i]) != NULL)
        break;
    }
    if (i >= 0) {
      /* There are quantifiers; remove and save them */
      let(&quantifiers, left(equation1, i + 2));
      let(&equation1, right(equation1, i + 3));
      eqnLen = strlen(equation1); /* Correct eqnLen */
      /* Check quantifier syntax */
      j = strlen(quantifiers);
      for (i = 0; i < j; i = i + 2) {
        if (strchr(QUANTIFIER_CONNECTIVES, quantifiers[i]) == NULL) {
          print2("?Error: Character position %ld should be @ or ] in %s%s\n",
              (long)(i + 1), quantifiers, equation1);
          print2("?Make sure input expression is in prenex normal form.\n");
          exit(0);
        }
        if (strchr(VAR_LIST, quantifiers[i + 1]) == NULL
            || quantifiers[i + 1] == 0) {
          print2(
              "?Error: Character position %ld should be a variable in %s%s\n",
              (long)(i + 2), quantifiers, equation1);
          print2("?Make sure input expression is in prenex normal form.\n");
          exit(0);
        }
        for (k = 0; k < j; k = k + 2) {
          if (k == i) continue;
          if (quantifiers[i + 1] == quantifiers[k + 1]) {
            print2("?Error: Variable %c is quantified twice in %s%s\n",
                quantifiers[i + 1], quantifiers, equation1);
            exit(0);
          }
        }
      }
    }

  } /* if (!recursiveCall) */

  subEqn1Len = subEqnLen(equation1);
  let(&subEqn1, left(equation1, subEqn1Len));

  if (subEqn1Len == eqnLen) {
    /* Handle unary prefix operators */
    if (equation1[0] == NEG_OPER || equation1[0] == NOT_OPER) {
      if (equation1[0] == NEG_OPER) {
        /* Check to make sure it does not scope metalogic or relations */
        j = strlen(equation1);
        for (i = 1; i < j; i++) {
          if (strchr(LOGIC_AND_RELATION_CONNECTIVES, equation1[i]) != NULL) {
            print2("?Error: %c should not be in scope of %c in %s\n",
                equation1[i], equation1[0], equation1);
            exit(0);
          }
        }
      }
      recursiveCall++;
      polSubEqn1 = toPolish(right(equation1, 2));
      recursiveCall--;

      /* Make sure a logical connective does scope a wff */
      if (equation1[0] == NOT_OPER) {
        if (strchr(LOGIC_AND_RELATION_CONNECTIVES, polSubEqn1[0]) == NULL) {
          print2("?Error:  %c should scope wffs in %s but %s is not a wff\n",
              NOT_OPER, equation1, right(subEqn1, 2));
          exit(0);
        }
      }

      let(&polEqn, cat(left(equation1, 1), polSubEqn1, NULL));
      goto exitPoint;
    }

    /* Handle expression enclosed in parentheses */
    if (equation1[0] == '(') {
      /* Strip parentheses */
      recursiveCall++;
      polEqn = toPolish(seg(equation1, 2, eqnLen - 1));
      recursiveCall--;
    } else {
      if (subEqn1Len != 1) {
        print2("?Error:  Expected expression %s to be length 1\n",
            equation1);
        exit(0);
      }
      if (strchr(cat(VAR_LIST, "01", NULL), equation1[0]) == NULL) {
        print2("?Error:  Expected %s to be a variable or 0 or 1\n",
            equation1);
        exit(0);
      }
      /* It's a variable or constant */
      let(&polEqn, subEqn1);
    }
    goto exitPoint;
  } /* if (subEqn1Len == eqnLen) */

  operation = equation1[subEqn1Len];
  if (strchr(ALL_BIN_CONNECTIVES, operation) == NULL) {
    print2("?Error:  Expected %c to be a binary connective in %s\n",
        operation, equation1);
    exit(0);
  }
  subEqn2Len = subEqnLen(right(equation1, subEqn1Len + 2));
  let(&subEqn2, right(equation1, subEqn1Len + 2));
  if (subEqn1Len + 1 + subEqn2Len != eqnLen) {
    print2("?Error:  Expected %s not %s after %c in %s\n",
        mid(equation1, subEqn1Len + 2, subEqn2Len), subEqn2,
        operation, equation1);
    exit(0);
  }
  /* Should be caught by above error check */
  if (subEqn2Len != strlen(subEqn2)) bug(250);

  /* Make sure a lattice operator doesn't scope a wff */
  if (strchr(OPER_AND_RELATION_BIN_CONNECTIVES, operation) != NULL) {
    /* Check to make sure it does not scope metalogic or relations */
    for (i = 0; i < subEqn1Len; i++) {
      if (strchr(LOGIC_AND_RELATION_CONNECTIVES, subEqn1[i]) != NULL) {
        print2("?Error: %c should not be in scope of %c in %s\n",
            subEqn1[i], operation, equation1);
        exit(0);
      }
    }
    for (i = 0; i < subEqn2Len; i++) {
      if (strchr(LOGIC_AND_RELATION_CONNECTIVES, subEqn2[i]) != NULL) {
        print2("?Error: %c should not be in scope of %c in %s\n",
            subEqn2[i], operation, equation1);
        exit(0);
      }
    }
  }

  /* Build the polish version */
  recursiveCall++;
  polSubEqn1 = toPolish(subEqn1);
  polSubEqn2 = toPolish(subEqn2);
  recursiveCall--;

  /* Make sure a logical connective does scope a wff */
  if (strchr(LOGIC_BIN_CONNECTIVES, operation) != NULL) {
    if (strchr(LOGIC_AND_RELATION_CONNECTIVES, polSubEqn1[0]) == NULL) {
      print2("?Error:  %c should scope wffs in %s but %s is not a wff\n",
          operation, equation1, subEqn1);
      exit(0);
    }
    if (strchr(LOGIC_AND_RELATION_CONNECTIVES, polSubEqn2[0]) == NULL) {
      print2("?Error:  %c should scope wffs in %s but %s is not a wff\n",
          operation, equation1, subEqn2);
      exit(0);
    }
  }

  let(&polEqn, cat(chr(operation), polSubEqn1, polSubEqn2, NULL));

 exitPoint:
  if (!recursiveCall
      && strchr(LOGIC_AND_RELATION_CONNECTIVES, polEqn[0]) == NULL) {
    print2("?Error:  %s is a term, not a wff\n", equation1);
    exit(0);
  }

  if (!recursiveCall) {
    /* Place any quantifiers back onto result */
    let(&polEqn, cat(quantifiers, polEqn, NULL));
  }

  /* Print the Polish subequation for debugging */
  /*print2("%ld %s\n",recursiveCall, polEqn);*/

  /* Deallocate strings */
  let(&equation1, "");
  let(&subEqn1, "");
  let(&subEqn2, "");
  let(&polSubEqn1, "");
  let(&polSubEqn2, "");

  return polEqn;

} /* toPolish */


/* Called by toPolish */
/* Returns length of first subequation */
long subEqnLen(vstring subEqn)
{
  long i, j, k;
  i = 0;
  j = 0;
  k = strlen(subEqn);
  while (1) {
    if (i >= k) break;
    if (subEqn[i] == NEG_OPER || subEqn[i] == NOT_OPER) {
      i++;
      continue;
    }
    if (subEqn[i] == '(') {
      j++;
      i++;
      continue;
    }
    if (subEqn[i] == ')') {
      j--;
    }
    i++;
    if (j == 0) break;
  }
  return i;
} /* subEqnLen */



/* ***Note:  The caller must deallocate returned string */
/* Convert Polish to normal notation */
wideVstring wideFromPolish(wideVstring polishEqn)
{
  /* This function converts a theorem in Polish notation to one
     in parentheses notation */
  wideVstring stack[MAX_STACK2];
  long i, stackPtr;
  long maxStack = 0;
  wideVstring stackEntry = wideNullString;
  wideVstring ch = wideNullString;
  wideVstring polishEqn1 = wideNullString;
  wideLet(&polishEqn1, polishEqn); /* In case temp alloc string is passed in */

  stackPtr = 0;
  for (i = wideLen(polishEqn1); i >= 1; i--) {
    wideLet(&ch, wideMid(polishEqn1, i, 1));
    if (ch[0] == (wideChar)NEG_OPER || ch[0] == (wideChar)NOT_OPER) {
      if (stackPtr > 0) {
        wideLet(&(stack[stackPtr]), wideCat(ch, stack[stackPtr], NULL));
      } else {
        print2("?Error 8: Stack underflow at %ld\n", i);
        exit(0);
      }
    } else {
      if (wideChrInStr(1, WIDE_ALL_BIN_CONNECTIVES, ch[0])) {
        if (stackPtr > 1) {
          stackPtr--;
          wideLet(&(stack[stackPtr]),
              wideCat(wide("("), stack[stackPtr + 1], ch,
              stack[stackPtr], wide(")"), NULL));
        } else {
          print2("?Error 9:  Stack underflow at %ld\n", i);
          exit(0);
        }
      } else { /* Variable assumed */
        stackPtr++;
        if (stackPtr >= MAX_STACK2) {
          print2(
           "?Error 12:  Stack overflow - increase MAX_STACK2 and recompile\n");
          exit(0);
        }
        if (stackPtr > maxStack) {
          maxStack = stackPtr;
          stack[stackPtr] = wideNullString;
        }
        wideLet(&(stack[stackPtr]), ch);
      }
    }
  } /* next i */
  if (stackPtr != 1) {
    print2("?Error 10: Stack not emptied\n");
    exit(0);
  }
  /* Deallocate vstring array */
  for (i = 2; i <= maxStack; i++) {
    wideLet(&(stack[i]), wideNullString);
  }
  wideLet(&ch, wideNullString);
  wideLet(&stackEntry, wideNullString);
  wideLet(&polishEqn1, wideNullString);
  return (stack[stackPtr]);
} /* wideFromPolish */


/* ***Note:  The caller must deallocate returned string */
/* Convert Polish to normal notation */
vstring fromPolish(vstring polishEqn)
{
  long l, i;
  vstring sout = "";
  wideVstring wsout;
  unsigned char c;
  wsout = wideFromPolish(wide(polishEqn));
  l = wideLen(wsout);
  let(&sout, space(l));
  for (i = 0; i < l; i++) {
    /* Should never be called with non-ASCII */
    if (wsout[i] > /*255*/ 127) bug(250); /* 127 = extra conservative */
    c = wsout[i];
    sout[i] = c;
  }
  wideLet(&wsout, wideNullString); /* Deallocate */
  return sout;
}


/* Convert a printable string to internal upper ASCII */
/* (Obsolete:) */
/* This function converts ascii "&a", "&b", ... to 'a'+128, 'b'+128,... */
/* New format: */
/* This function converts hex ascii ":01", ":02", ... to 129, 130,... */
/* Use like any vstring function (left, right,...) */
/* This function (used to parse lattice.c Hasse diagrams only)
   does not (and needs not) deal with the metalogical
   TRUE_CONST and FALSE_CONST */
wideVstring unPrintableString(vstring sin)
{
  wideVstring sout;
  long i, j, n;
  wideChar c;
  char *hexdigits = "0123456789ABCDEF";
  char *d1;
  char *d2;
  j = strlen(sin);
  n = 0;
  /*for (i = 0; i < j; i++) if (sin[i] == '&') n++;*/
  for (i = 0; i < j; i++) if (sin[i] == ':') n += 2;
  sout = tempAlloc(j - n + 1);
  sout[j - n] = WIDE_ENDCHAR;
  n = 0;
  for (i = 0; i < j; i++) {
    if (sin[i] == ':') {
      /*
      c = sin[i + 1];
      c += 128;
      sout[i - n] = c;
      n++;
      */
      /* Convert hex "01" -> 129, "02" -> 130,..., "7F" -> 255 */
      d1 = strchr(hexdigits, sin[i + 1]);
      d2 = strchr(hexdigits, sin[i + 2]);
      if (d1 == NULL || d2 == NULL) bug(107);
      c = 128 + 16 * (d1 - hexdigits) + (d2 - hexdigits);
      sout[i - n] = c;
      n += 2;
      i++;
    } else {
      sout[i - n] = (wideChar)(sin[i]);
    }
  }
  return sout;
}

/* Return a printable string */
/* (Obsolete:) */
/* This function converts ascii 'a'+128, 'b'+128,... to "&a", "&b", ... */
/* (Obsolete New:) */
/* This function converts ascii 129, 130,...,255 to ":01", ":02",... ":7F" */
/* (New:) */
/* This function converts ascii 128, 129,... to "#0;", "#1;",...,"#10;",... */
/* It also converts FALSE_CONST and TRUE_CONST to "F" and "T" - which
   could be ambiguous with node names but usually shouldn't cause user
   confusion */
/* Use like any vstring function (left, right,...) */
vstring printableString(wideVstring sin)
{
  vstring sout;
  long i, j, k, l, m, n, d;
  j = wideLen(sin);
  n = 0;
  for (i = 0; i < j; i++) {
    k = (wideChar)(sin[i]);
    /* FALSE_CONST and TRUE_CONST will normally be less than 127
       (e.g. 1 and 2) but since it is not strictly required we
       AND them in for extra safety */
    if (k > 127 && k != FALSE_CONST && k != TRUE_CONST) {
      m = k - 128; /* The extended node name */
      n = n + 2; /* For one-digit case e.g. #0; */
      while (m >= 10) { /* Allow space for > one-digit numbers */
        n++;
        m = m / 10;
      }
    }
    /* Map lower ASCII to ^@, ^A, ^B,... */
    if (k < 32 && k != FALSE_CONST && k != TRUE_CONST) n++;
  }
  sout = tempAlloc(j + n + 1);
  sout[j + n] = 0;
  n = 0;
  for (i = 0; i < j; i++) {
    k = (wideChar)(sin[i]);
    if (k == FALSE_CONST) {
      sout[i + n] = 'F';
    } else {
      if (k == TRUE_CONST) {
        sout[i + n] = 'T';
      } else {
        if (k > 127) {
          sout[i + n] = '#';
          n++;
          m = k - 128; /* The extended node name */
          /* Count # digits in m */
          d = 1;
          while (m >= 10) {
            d++;
            m = m / 10;
          }
          m = k - 128;
          for (l = d - 1; l >= 0; l--) {
            sout[i + n + l] = "0123456789"[m - 10 * (m / 10)];
            m = m / 10;
          }
          n = n + d;
          sout[i + n] = ';';
        } else {
          if (k < 32) {
            sout[i + n] = '^';
            n++;
            sout[i + n] = k + 64; /* 0=^@, 1=^A, 2=^B,... */
          } else {
            sout[i + n] = k;
          }
        }
      }
    }
  }
  return (sout);
}

long nodeToAtom(long node)
{
  /* Returns the atom number corresponding to a node number if there is one,
     otherwise returns 0 */
  /* Node for atom */
  if (node >= 2 && node <= atoms + 1) return node - 1;
  /* Node for complement atom */
  if (node >= atoms + 3 && node <= 2 * atoms + 2) return node - atoms - 2;
  return 0; /* 1, 0, or extra 2^4 nodes */
}


/* Use like any vstring function (left, right,...) */
vstring printableAtomName(long atomNum)
{
  /* Returns the ASCII name corresponding to an atom
     1,2,3,.....  =>
     12...9A...Za...`{|}~+1+2...+|+}+~++1...++~+++1.... */
  long m, k;
  vstring atomName = "";
  if (atomNum <= 0) return ""; /* Not an atom (e.g. 0 or 1 node) */
  m = 1;
  k = atomNum;
  while (k > ATOM_MAPLen) {
    /* Handle extended notation */
    m++;
    k -= ATOM_MAPLen;
  }
  /*let(&atomName, space(m));*/ /* Pre-allocate space for atom name */
  atomName = tempAlloc(m + 1); /* Pre-allocate space for atom name */
  atomName[m] = 0;
  k = atomNum;
  m = 0;
  while (k > ATOM_MAPLen) {
    /* Handle extended notation */
    atomName[m] = '+';
    m++;
    k -= ATOM_MAPLen;
  }
  atomName[m] = ATOM_MAP[k - 1];
  return atomName;
}



/*****************************************************************************/
/*       Copyright (C) 2000  NORMAN D. MEGILL  <nm@alum.mit.edu>             */
/*             License terms:  GNU General Public License                    */
/*****************************************************************************/

/*34567890123456 (79-character line to adjust text window width) 678901234567*/
/*
mmvstr.h - VMS-BASIC variable length string library routines header
This is a collection of useful built-in string functions available in VMS BASIC.
*/

/**************************************************************************

Variable-length string handler
------------------------------

     This collection of string-handling functions emulate most of the
string functions of VMS BASIC.  The objects manipulated by these functions
are strings of a special type called 'vstring' which
have no pre-defined upper length limit but are dynamically allocated
and deallocated as needed.  To use the vstring functions within a program,
all vstrings must be initially set to the null string when declared or
before first used, for example:

        vstring string1 = "";
        vstring stringArray[] = {"","",""};

        vstring bigArray[100][10]; /- Must be initialized before using -/
        int i,j;
        for (i=0; i<100; i++)
          for (j=0; j<10; j++)
            bigArray[i][j] = ""; /- Initialize -/


     After initialization, vstrings should be assigned with the 'let(&'
function only; for example the statements

        let(&string1,"abc");
        let(&string1,string2);
        let(&string1,left(string2,3));

all assign the second argument to 'string1'.  The 'let(&' function must
not be used to initialize a vstring for the first time.

     The 'cat' function emulates the '+' concatenation operator in BASIC.
It has a variable number of arguments, and the last argument should always
be NULL.  For example,

        let(&string1,cat("abc","def",NULL));

assigns "abcdef" to 'string1'.  Warning: 0 will work instead of NULL on the
VAX but not on the Macintosh, so always use NULL.

     All other functions are generally used exactly like their BASIC
equivalents.  For example, the BASIC statement

        let string1$=left$("def",len(right$("xxx",2)))+"ghi"+string2$

is emulated in c as

        let(&string1,cat(left("def",len(right("xxx",2))),"ghi",string2,NULL));

Note that ANSII c does not allow "$" as part of an identifier
name, so the names in c have had the "$" suffix removed.

     The string arguments of the vstring functions may be either standard c
strings or vstrings (except that the first argument of the 'let(&' function
must be a vstring).  The standard c string functions may use vstrings or
vstring functions as their string arguments, as long as the vstring variable
itself (which is a char * pointer) is not modified and no attempt is made to
increase the length of a vstring.  Caution must be excercised when
assigning standard c string pointers to vstrings or the results of
vstring functions, as the memory space may be deallocated when the
'let(&' function is next executed.  For example,

        char *stdstr; /- A standard c string pointer -/
         ...
        stdstr=left("abc",2);

will assign "ab" to 'stdstr', but this assignment will be lost when the
next 'let(&' function is executed.  To be safe, use 'strcpy':

        char stdstr1[80]; /- A fixed length standard c string -/
         ...
        strcpy(stdstr1,left("abc",2));

Here, of course, the user must ensure that the string copied to 'stdstr1'
does not exceed 79 characters in length.

     The vstring functions allocate temporary memory whenever they are called.
This temporary memory is deallocated whenever a 'let(&' assignment is
made.  The user should be aware of this when using vstring functions
outside of 'let(&' assignments; for example

        for (i=0; i<10000; i++)
          print2("%s\n",left(string1,70));

will allocate another 70 bytes or so of memory each pass through the loop.
If necessary, dummy 'let(&' assignments can be made periodically to clear
this temporary memory:

        for (i=0; i<10000; i++)
          {
          print2("%s\n",left(string1,70));
          let(&dummy,"");
          }

It should be noted that the 'linput' function assigns its target string
with 'let(&' and thus has the same effect as 'let(&'.

************************************************************************/


void *tempAlloc(long size)    /* String memory allocation/deallocation */
{
  /* When "size" is >0, "size" bytes are allocated. */
  /* When "size" is 0, all memory previously allocated with this */
  /* function is deallocated. */
  /* EXCEPT:  When startTempAllocStack != 0, the freeing will start at
     startTempAllocStack. */
  int i;
  if (size) {
    if (tempAllocStackTop>=(MAX_ALLOC_STACK-1)) {
      print2("?Error: Temporary string stack overflow\n");
      bug(101);
    }
    if (!(tempAllocStack[tempAllocStackTop++]=malloc(size))) {
      print2("?Error: Temporary string allocation failed\n");
      bug(102);
    }
    return (tempAllocStack[tempAllocStackTop-1]);
  } else {
    for (i=startTempAllocStack; i<tempAllocStackTop; i++) {
      free(tempAllocStack[i]);
    }
    tempAllocStackTop=startTempAllocStack;
    return (NULL);
  }
}


/* Make string have temporary allocation to be released by next let() */
/* Warning:  after makeTempAlloc() is called, the string may NOT be
   assigned again with let() */
void makeTempAlloc(vstring s)
{
    if (tempAllocStackTop>=(MAX_ALLOC_STACK-1)) {
      print2("?Error: Temporary string stack overflow\n");
      bug(103);
    }
    tempAllocStack[tempAllocStackTop++]=s;
}


void let(vstring *target,vstring source)        /* String assignment */
/* This function must ALWAYS be called to make assignment to */
/* a vstring in order for the memory cleanup routines, etc. */
/* to work properly.  If a vstring has never been assigned before, */
/* it is the user's responsibility to initialize it to "" (the */
/* null string). */
{
  long targetLength,sourceLength;

  sourceLength=strlen(source);  /* Save its length */
  targetLength=strlen(*target); /* Save its length */
  if (targetLength) {
    if (sourceLength) { /* source and target are both nonzero length */

      if (targetLength>=sourceLength) { /* Old string has room for new one */
        strcpy(*target,source); /* Re-use the old space to save CPU time */
      } else {
        /* Free old string space and allocate new space */
        free(*target);  /* Free old space */
        *target=malloc(sourceLength+1); /* Allocate new space */
        if (!*target) {
          print2("?Error: String memory couldn't be allocated\n");
          bug(104);
        }
        strcpy(*target,source);
      }

    } else {    /* source is 0 length, target is not */
      free(*target);
      *target= "";
    }
  } else {
    if (sourceLength) { /* target is 0 length, source is not */
      *target=malloc(sourceLength+1);   /* Allocate new space */
      if (!*target) {
        print2("?Error: Could not allocate string memory\n");
        bug(105);
      }
      strcpy(*target,source);
    } else {    /* source and target are both 0 length */
      *target= "";
    }
  }

  tempAlloc(0); /* Free up temporary strings used in expression computation */

}


void wideLet(wideVstring *target, wideVstring source)
                                                   /* Wide string assignment */
/* This function must ALWAYS be called to make assignment to */
/* a wideVstring in order for the memory cleanup routines, etc. */
/* to work properly.  If a wideVstring has never been assigned before, */
/* it is the user's responsibility to initialize it to the empty string). */
{
  long targetLength,sourceLength;

  sourceLength = wideLen(source);  /* Save its length */
  targetLength = wideLen(*target); /* Save its length */
  if (targetLength) {
    if (sourceLength) { /* source and target are both nonzero length */
      if (targetLength >= sourceLength) { /* Old string has room for new one */
        wideCpy(*target, source); /* Re-use the old space to save CPU time */
      } else {
        /* Free old string space and allocate new space */
        free(*target);  /* Free old space */
        *target = malloc((sourceLength + 1) * sizeof(wideChar));
                                                       /* Allocate new space */
        if (!*target) {
          print2("?Error: Wide string memory couldn't be allocated\n");
          bug(104);
        }
        wideCpy(*target,source);
      }
    } else {    /* source is 0 length, target is not */
      free(*target);
      *target = wideNullString;
    }
  } else {
    if (sourceLength) { /* target is 0 length, source is not */
      *target = malloc((sourceLength + 1) * sizeof(wideChar));
                                                       /* Allocate new space */
      if (!*target) {
        print2("?Error: Could not allocate wide string memory\n");
        bug(105);
      }
      wideCpy(*target, source);
    } else {    /* source and target are both 0 length */
      *target = wideNullString;
    }
  }

  tempAlloc(0); /* Free up temporary strings used in expression computation */

}




vstring cat(vstring string1,...)        /* String concatenation */
#define MAX_CAT_ARGS 30
{
  va_list ap;   /* Declare list incrementer */
  vstring arg[MAX_CAT_ARGS];    /* Array to store arguments */
  long argLength[MAX_CAT_ARGS]; /* Array to store argument lengths */
  int numArgs=1;        /* Define "last argument" */
  int i;
  long j;
  vstring ptr;

  arg[0]=string1;       /* First argument */

  va_start(ap,string1); /* Begin the session */
  while ((arg[numArgs++]=va_arg(ap,char *)))
        /* User-provided argument list must terminate with 0 */
    if (numArgs>=MAX_CAT_ARGS-1) {
      print2("?Error: Too many cat() arguments\n");
      bug(106);
    }
  va_end(ap);           /* End var args session */

  numArgs--;    /* The last argument (0) is not a string */

  /* Find out the total string length needed */
  j=0;
  for (i=0; i<numArgs; i++) {
    argLength[i]=strlen(arg[i]);
    j=j+argLength[i];
  }
  /* Allocate the memory for it */
  ptr=tempAlloc(j+1);
  /* Move the strings into the newly allocated area */
  j=0;
  for (i=0; i<numArgs; i++) {
    strcpy(ptr+j,arg[i]);
    j=j+argLength[i];
  }
  return (ptr);

}


wideVstring wideCat(wideVstring string1, ...)  /* Wide string concatenation */
{
  va_list ap;   /* Declare list incrementer */
  wideVstring arg[MAX_CAT_ARGS];    /* Array to store arguments */
  long argLength[MAX_CAT_ARGS]; /* Array to store argument lengths */
  int numArgs = 1;        /* Define "last argument" */
  int i;
  long j;
  wideVstring ptr;

  arg[0] = string1;       /* First argument */

  va_start(ap, string1); /* Begin the session */
  while ((arg[numArgs++] = va_arg(ap, wideVstring)))
        /* User-provided argument list must terminate with 0 */
    if (numArgs >= MAX_CAT_ARGS - 1) {
      print2("?Error: Too many cat() arguments\n");
      bug(106);
    }
  va_end(ap);           /* End var args session */

  numArgs--;    /* The last argument (NULL) is not a string */

  /* Find out the total string length needed */
  j = 0;
  for (i = 0; i < numArgs; i++) {
    argLength[i] = wideLen(arg[i]);
    j = j + argLength[i];
  }
  /* Allocate the memory for it */
  ptr = tempAlloc((j + 1) * sizeof(wideChar));
  /* Move the strings into the newly allocated area */
  j = 0;
  for (i = 0; i < numArgs; i++) {
    wideCpy(ptr + j, arg[i]);
    j = j + argLength[i];
  }
  return (ptr);
}


/* input a line from the user or from a file */
vstring linput(FILE *stream,vstring ask,vstring *target)
{
  /*
    BASIC:  linput "what";a$
    c:      linput(NULL,"what?",&a);

    BASIC:  linput #1,a$                        (error trap on EOF)
    c:      if (!linput(file1,NULL,&a)) break;  (break on EOF)

  */
  /* This function prints a prompt (if 'ask' is not NULL), gets a line from
    the stream, and assigns it to target using the let(&...) function.
    NULL is returned when end-of-file is encountered.  The vstring
    *target MUST be initialized to "" or previously assigned by let(&...)
    before using it in linput. */
  char f[10001]; /* Allow up to 10000 characters */
  if (ask) print2("%s",ask);
  if (stream == NULL) stream = stdin;
  if (!fgets(f,10000,stream)) {
    /* End of file */
    return NULL;
  }
  f[10000]=0;     /* Just in case */
  f[strlen(f)-1]=0;     /* Eliminate new-line character */
  /* Assign the user's input line */
  let(target,f);
  return *target;
}


/* Find out the length of a string */
long len(vstring s)
{
  return (strlen(s));
}


/* Find out the length of a wide string, analogous to strlen */
long wideLen(wideVstring s)
{
  long n;
  for (n = 0; *s != WIDE_ENDCHAR; s++)
    n++;
  return n;
}

/* Copy wide string s to t, analogous to strcpy */
void wideCpy(wideVstring t, wideVstring s)
{
  while ((*t++ = *s++) != WIDE_ENDCHAR)
    ;
}


/* Extract sin from character position start to stop into sout */
vstring seg(vstring sin,long start,long stop)
{
  vstring sout;
  long len;
  if (start<1) start=1;
  if (stop<1) stop=0;
  len=stop-start+1;
  if (len<0) len=0;
  sout=tempAlloc(len+1);
  strncpy(sout,sin+start-1,len);
  sout[len]=0;
  return (sout);
}


/* Extract sin from character position start for length len */
vstring mid(vstring sin,long start,long len)
{
  vstring sout;
  if (start<1) start=1;
  if (len<0) len=0;
  sout=tempAlloc(len+1);
  strncpy(sout,sin+start-1,len);
/*??? Should db be substracted from if len > end of string? */
  sout[len]=0;
  return (sout);
}


/* Extract sin from character position start for length len */
wideVstring wideMid(wideVstring sin, long start, long len)
{
  wideVstring sout;
  long i, l;
  if (start < 1) start = 1;
  l = wideLen(sin) - start + 1;
  if (len > l) len = l;
  if (len < 0) len = 0;
  sout = tempAlloc((len + 1) * sizeof(wideChar));
  /* Emulate strncpy(sout,sin+start-1,len); */
  for (i = 0; i < len; i++) sout[i] = sin[i + start - 1];
  sout[len] = WIDE_ENDCHAR;
  return (sout);
}


/* Extract leftmost n characters */
vstring left(vstring sin,long n)
{
  vstring sout;
  if (n < 0) n = 0;
  sout=tempAlloc(n+1);
  strncpy(sout,sin,n);
  sout[n]=0;
  return (sout);
}


/* Extract leftmost n characters */
wideVstring wideLeft(wideVstring sin, long n)
{
  wideVstring sout;
  long i, l;
  if (n < 0) n = 0;
  sout = tempAlloc((n + 1) * sizeof(wideChar));

  /* Emulate strncpy(sout, sin, n); */
  l = wideLen(sin);
  if (n > l) n = l;
  for (i = 0; i < n; i++) sout[i] = sin[i];
  sout[n] = WIDE_ENDCHAR;

  return (sout);
}


/* Extract after character n */
vstring right(vstring sin,long n)
{
  /*??? We could just return &sin[n-1], but this is safer for debugging. */
  vstring sout;
  long i;
  if (n<1) n=1;
  i = strlen(sin);
  if (n>i) return ("");
  sout = tempAlloc(i - n + 2);
  strcpy(sout,&sin[n-1]);
  return (sout);
}


/* Extract after character n */
wideVstring wideRight(wideVstring sin, long n)
{
  /*??? We could just return &sin[n-1], but this is safer for debugging. */
  wideVstring sout;
  long i;
  if (n < 1) n = 1;
  i = wideLen(sin);
  if (n > i) return (wideNullString);
  sout = tempAlloc((i - n + 2) * sizeof(wideChar));
  wideCpy(sout, &sin[n - 1]);
  return (sout);
}


/* Emulate VMS BASIC edit$ command */
vstring edit(vstring sin,long control)
#define isblank_(c) ((c==' ') || (c=='\t'))
{
/*
EDIT$
  Syntax
         str-vbl = EDIT$(str-exp, int-exp)
     Values   Effect
     1        Trim parity bits
     2        Discard all spaces and tabs
     4        Discard characters: CR, LF, FF, ESC, RUBOUT, and NULL
     8        Discard leading spaces and tabs
     16       Reduce spaces and tabs to one space
     32       Convert lowercase to uppercase
     64       Convert [ to ( and ] to )
     128      Discard trailing spaces and tabs
     256      Do not alter characters inside quotes

     (non-BASIC extensions)
     512      Convert uppercase to lowercase
     1024     Tab the line (convert spaces to equivalent tabs)
     2048     Untab the line (convert tabs to equivalent spaces)
     4096     Convert VT220 screen print frame graphics to -,|,+ characters
*/
  vstring sout;
  long i,j,k;
  int last_char_is_blank;
  int trim_flag,discardcr_flag,bracket_flag,quote_flag,case_flag;
  int alldiscard_flag,leaddiscard_flag,traildiscard_flag,reduce_flag;
  int processing_inside_quote=0;
  int lowercase_flag, tab_flag, untab_flag, screen_flag;
  unsigned char graphicsChar;

  /* Set up the flags */
  trim_flag=control & 1;
  alldiscard_flag=control & 2;
  discardcr_flag=control & 4;
  leaddiscard_flag=control & 8;
  reduce_flag=control & 16;
  case_flag=control & 32;
  bracket_flag=control & 64;
  traildiscard_flag=control & 128;
  quote_flag=control & 256;

  /* Non-BASIC extensions */
  lowercase_flag = control & 512;
  tab_flag = control & 1024;
  untab_flag = control & 2048;
  screen_flag = control & 4096; /* Convert VT220 screen prints to |,-,+
                                   format */

  /* Copy string */
  i = strlen(sin) + 1;
  if (untab_flag) i = i * 7;
  sout=tempAlloc(i);
  strcpy(sout,sin);

  /* Discard leading space/tab */
  i=0;
  if (leaddiscard_flag)
    while ((sout[i]!=0) && isblank_(sout[i]))
      sout[i++]=0;

  /* Main processing loop */
  while (sout[i]!=0) {

    /* Alter characters inside quotes ? */
    if (quote_flag && ((sout[i]=='"') || (sout[i]=='\'')))
       processing_inside_quote=~processing_inside_quote;
    if (processing_inside_quote) {
       /* Skip the rest of the code and continue to process next character */
       i++; continue;
    }

    /* Discard all space/tab */
    if ((alldiscard_flag) && isblank_(sout[i]))
        sout[i]=0;

    /* Trim parity (eighth?) bit */
    if (trim_flag)
       sout[i]=sout[i] & 0x7F;

    /* Discard CR,LF,FF,ESC,BS */
    if ((discardcr_flag) && (
         (sout[i]=='\015') || /* CR  */
         (sout[i]=='\012') || /* LF  */
         (sout[i]=='\014') || /* FF  */
         (sout[i]=='\033') || /* ESC */
         /*(sout[i]=='\032') ||*/ /* ^Z */ /* DIFFERENCE won't work w/ this */
         (sout[i]=='\010')))  /* BS  */
      sout[i]=0;

    /* Convert lowercase to uppercase */
    if ((case_flag) && (islower(sout[i])))
       sout[i]=toupper(sout[i]);

    /* Convert [] to () */
    if ((bracket_flag) && (sout[i]=='['))
       sout[i]='(';
    if ((bracket_flag) && (sout[i]==']'))
       sout[i]=')';

    /* Convert uppercase to lowercase */
    if ((lowercase_flag) && (islower(sout[i])))
       sout[i]=tolower(sout[i]);

    /* Convert VT220 screen print frame graphics to +,|,- */
    if (screen_flag) {
      graphicsChar = sout[i]; /* Need unsigned char for >127 */
      /* vt220 */
      if (graphicsChar >= 234 && graphicsChar <= 237) sout[i] = '+';
      if (graphicsChar == 241) sout[i] = '-';
      if (graphicsChar == 248) sout[i] = '|';
      /* vt100 */
      if (graphicsChar == 218 /*up left*/ || graphicsChar == 217 /*lo r*/
          || graphicsChar == 191 /*up r*/ || graphicsChar == 192 /*lo l*/)
        sout[i] = '+';
      if (graphicsChar == 196) sout[i] = '-';
      if (graphicsChar == 179) sout[i] = '|';
    }

    /* Process next character */
    i++;
  }
  /* sout[i]=0 is the last character at this point */

  /* Clean up the deleted characters */
  for (j=0,k=0; j<=i; j++)
    if (sout[j]!=0) sout[k++]=sout[j];
  sout[k]=0;
  /* sout[k]=0 is the last character at this point */

  /* Discard trailing space/tab */
  if (traildiscard_flag) {
    --k;
    while ((k>=0) && isblank_(sout[k])) --k;
    sout[++k]=0;
  }

  /* Reduce multiple space/tab to a single space */
  if (reduce_flag) {
    i=j=last_char_is_blank=0;
    while (i<=k-1) {
      if (!isblank_(sout[i])) {
        sout[j++]=sout[i++];
        last_char_is_blank=0;
      } else {
        if (!last_char_is_blank)
          sout[j++]=' '; /* Insert a space at the first occurrence of a blank */
        last_char_is_blank=1; /* Register that a blank is found */
        i++; /* Process next character */
      }
    }
    sout[j]=0;
  }

  /* Untab the line */
  if (untab_flag || tab_flag) {

    /*
    DEF FNUNTAB$(L$)      ! UNTAB LINE L$
    I9%=1%
    I9%=INSTR(I9%,L$,CHR$(9%))
    WHILE I9%
      L$=LEFT(L$,I9%-1%)+SPACE$(8%-((I9%-1%) AND 7%))+RIGHT(L$,I9%+1%)
      I9%=INSTR(I9%,L$,CHR$(9%))
    NEXT
    FNUNTAB$=L$
    FNEND
    */

    k = strlen(sout);
    for (i = 1; i <= k; i++) {
      if (sout[i - 1] != '\t') continue;
      for (j = k; j >= i; j--) {
        sout[j + 8 - ((i - 1) & 7) - 1] = sout[j];
      }
      for (j = i; j < i + 8 - ((i - 1) & 7); j++) {
        sout[j - 1] = ' ';
      }
      k = k + 8 - ((i - 1) & 7);
    }
  }

  /* Tab the line */
  if (tab_flag) {

    /*
    DEF FNTAB$(L$)        ! TAB LINE L$
    I9%=0%
    FOR I9%=8% STEP 8% WHILE I9%<LEN(L$)
      J9%=I9%
      J9%=J9%-1% UNTIL ASCII(MID(L$,J9%,1%))<>32% OR J9%=I9%-8%
      IF J9%<=I9%-2% THEN
        L$=LEFT(L$,J9%)+CHR$(9%)+RIGHT(L$,I9%+1%)
        I9%=J9%+1%
      END IF
    NEXT I9%
    FNTAB$=L$
    FNEND
    */

    i = 0;
    k = strlen(sout);
    for (i = 8; i < k; i = i + 8) {
      j = i;
      while (sout[j - 1] == ' ' && j > i - 8) j--;
      if (j <= i - 2) {
        sout[j] = '\t';
        j = i;
        while (sout[j - 1] == ' ' && j > i - 8 + 1) {
          sout[j - 1] = 0;
          j--;
        }
      }
    }
    i = k;
    /* sout[i]=0 is the last character at this point */
    /* Clean up the deleted characters */
    for (j = 0, k = 0; j <= i; j++)
      if (sout[j] != 0) sout[k++] = sout[j];
    sout[k] = 0;
    /* sout[k]=0 is the last character at this point */
  }

  return (sout);
}


/* Return a string of the same character */
vstring string(long n, char c)
{
  vstring sout;
  long j=0;
  if (n<0) n=0;
  sout=tempAlloc(n+1);
  while (j<n) sout[j++]=c;
  sout[j]=0;
  return (sout);
}


/* Return a string of the same character */
wideVstring wideString(long n, wideChar c)
{
  wideVstring sout;
  long j = 0;
  if (n < 0) n = 0;
  sout = tempAlloc((n + 1) * sizeof(wideChar));
  while (j < n) sout[j++] = c;
  sout[j] = WIDE_ENDCHAR;
  return (sout);
}

/* Convert a character string to a wide string */
wideVstring wide(vstring s)
{
  long n, j;
  wideVstring sout;
  n = strlen(s);
  sout = tempAlloc((n + 1) * sizeof(wideChar));
  for (j = 0; j < n; j++) sout[j] = (wideChar)(s[j]);
  sout[n] = WIDE_ENDCHAR;
  return (sout);
}


/* Return a string of spaces */
vstring space(long n)
{
  return (string(n,' '));
}


/* Return a character given its ASCII value */
vstring chr(long n)
{
  vstring sout;
  sout=tempAlloc(2);
  sout[0]= n & 0xFF;
  sout[1]=0;
  return(sout);
}


/* Search for string2 in string 1 starting at start_position */
long instr(long start_position,vstring string1,vstring string2)
{
   char *sp1,*sp2;
   long ls1,ls2;
   long found=0;
   if (start_position<1) start_position=1;
   ls1=strlen(string1);
   ls2=strlen(string2);
   if (start_position>ls1) start_position=ls1+1;
   sp1=string1+start_position-1;
   while ((sp2=strchr(sp1,string2[0]))!=0) {
     if (strncmp(sp2,string2,ls2)==0) {
        found=sp2-string1+1;
        break;
     } else
        sp1=sp2+1;
   }
   return (found);
}


/* Search for wide char in wide string starting at start */
/* First char in string is position 1 (not 0), like instr() */
/* Returns 0 if not found */
long wideChrInStr(long start, wideVstring s, wideChar c)
{
  long l, i;
  l = wideLen(s);
  if (start < 1) start = 1;
  for (i = start - 1; i < l; i++) {
    if (s[i] == c) return i + 1;
  }
  return 0;
}


/* Translate string in sin to sout based on table.
   Table must be 256 characters long!! <- not true anymore? */
vstring xlate(vstring sin,vstring table)
{
  vstring sout;
  long len_table,len_sin;
  long i,j;
  long table_entry;
  char m;
  len_sin=strlen(sin);
  len_table=strlen(table);
  sout=tempAlloc(len_sin+1);
  for (i=j=0; i<len_sin; i++)
  {
    table_entry= 0x000000FF & (long)sin[i];
    if (table_entry<len_table)
      if ((m=table[table_entry])!='\0')
        sout[j++]=m;
  }
  sout[j]='\0';
  return (sout);
}


/* Returns the ascii value of a character */
long ascii_(vstring c)
{
  return (long)((unsigned char)(c[0]));
}

/* Returns the floating-point value of a numeric string */
double val(vstring s)
{
  /*
  return (atof(s));
  */
  /* 12/10/98 - NDM - atof may corrupt memory when processing
     random character strings.
     The implementation below makes best guess of value of any
     random string, ignoring commas, etc. and tolerating numbers
     suffixed with sign.  "E" notation is not handled. */
  double v = 0;
  char signFound = 0;
  double power = 1.0;
  long i, len;
  len = strlen(s);
  /* Scan from lsd backwards to minimize rounding errors */
  for (i = len - 1; i >= 0; i--) {
    switch (s[i]) {
      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
        v = v + ((double)(s[i] - '0')) * power;
        power = 10.0 * power;
        break;
      case '.':
        v = v / power;
        power = 1.0;
        break;
      case '-':
        signFound = 1;
        break;
    }
  }
  if (signFound) v = - v;
  return v;
}


/* Returns current date as an ASCII string */
vstring date()
{
        vstring sout;
        struct tm *time_structure;
        time_t time_val;
        char *month[12];

        /* (Aggregrate initialization is not portable) */
        /* (It must be done explicitly for portability) */
        month[0]="Jan";
        month[1]="Feb";
        month[2]="Mar";
        month[3]="Apr";
        month[4]="May";
        month[5]="Jun";
        month[6]="Jul";
        month[7]="Aug";
        month[8]="Sep";
        month[9]="Oct";
        month[10]="Nov";
        month[11]="Dec";

        time(&time_val);                        /* Retrieve time */
        time_structure=localtime(&time_val); /* Translate to time structure */
        sout=tempAlloc(12);
        /* "%02d" means leading zeros with min. field width of 2 */
        sprintf(sout,"%d-%s-%02d",
                time_structure->tm_mday,
                month[time_structure->tm_mon],
                (int)((time_structure->tm_year) % 100)); /* Y2K */
        return(sout);
}

/* Return current time as an ASCII string */
vstring time_()
{
        vstring sout;
        struct tm *time_structure;
        time_t time_val;
        int i;
        char *format;
        char *format1="%d:%d %s";
        char *format2="%d:0%d %s";
        char *am_pm[2];
        /* (Aggregrate initialization is not portable) */
        /* (It must be done explicitly for portability) */
        am_pm[0]="AM";
        am_pm[1]="PM";

        time(&time_val);                        /* Retrieve time */
        time_structure=localtime(&time_val); /* Translate to time structure */
        if (time_structure->tm_hour>=12) i=1;
        else                             i=0;
        if (time_structure->tm_hour>12) time_structure->tm_hour-=12;
        if (time_structure->tm_hour==0) time_structure->tm_hour=12;
        sout=tempAlloc(12);
        if (time_structure->tm_min>=10)
          format=format1;
        else
          format=format2;
        sprintf(sout,format,
                time_structure->tm_hour,
                time_structure->tm_min,
                am_pm[i]);
        return(sout);

}


/* Return a number as an ASCII string */
vstring str(double f)
{
  /* This function converts a floating point number to a string in the */
  /* same way that %f in printf does, except that trailing zeroes after */
  /* the one after the decimal point are stripped; e.g., it returns 7 */
  /* instead of 7.000000000000000. */
  vstring s;
  long i;
  s = tempAlloc(50);
  sprintf(s, "%f", f);
  if (strchr(s, '.') != 0) {              /* the string has a period in it */
    for (i = strlen(s) - 1; i > 0; i--) { /* scan string backwards */
      if (s[i] != '0') break;             /* 1st non-zero digit */
      s[i] = 0;                           /* delete the trailing 0 */
    }
    if (s[i] == '.') s[i] = 0;            /* delete trailing period */
  }
  return (s);
}


/* Return a number as an ASCII string */
vstring num1(double f)
{
  return (str(f));
}


/* Return a number as an ASCII string surrounded by spaces */
vstring num(double f)
{
  return (cat(" ",str(f)," ",NULL));
}


/*** NEW FUNCTIONS ADDED 11/25/98 ***/

/* Emulate PROGRESS "entry" and related string functions */
/* (PROGRESS is a 4-GL database language) */

/* A "list" is a string of comma-separated elements.  Example:
   "a,b,c" has 3 elements.  "a,b,c," has 4 elements; the last element is
   an empty string.  ",," has 3 elements; each is an empty string.
   In "a,b,c", the entry numbers of the elements are 1, 2 and 3 (i.e.
   the entry numbers start a 1, not 0). */

/* Returns a character string entry from a comma-separated
   list based on an integer position. */
/* If element is less than 1 or greater than number of elements
   in the list, a null string is returned. */
vstring entry(long element, vstring list)
{
  vstring sout;
  long commaCount, lastComma, i, len;
  if (element < 1) return ("");
  lastComma = -1;
  commaCount = 0;
  i = 0;
  while (list[i] != 0) {
    if (list[i] == ',') {
      commaCount++;
      if (commaCount == element) {
        break;
      }
      lastComma = i;
    }
    i++;
  }
  if (list[i] == 0) commaCount++;
  if (element > commaCount) return ("");
  len = i - lastComma - 1;
  if (len < 1) return ("");
  sout = tempAlloc(len + 1);
  strncpy(sout, list + lastComma + 1, len);
  sout[len] = 0;
  return (sout);
}

/* Emulate PROGRESS lookup function */
/* Returns an integer giving the first position of an expression
   in a comma-separated list. Returns a 0 if the expression
   is not in the list. */
long lookup(vstring expression, vstring list)
{
  long i, exprNum, exprPos;
  char match;

  match = 1;
  i = 0;
  exprNum = 0;
  exprPos = 0;
  while (list[i] != 0) {
    if (list[i] == ',') {
      exprNum++;
      if (match) {
        if (expression[exprPos] == 0) return exprNum;
      }
      exprPos = 0;
      match = 1;
      i++;
      continue;
    }
    if (match) {
      if (expression[exprPos] != list[i]) match = 0;
    }
    i++;
    exprPos++;
  }
  exprNum++;
  if (match) {
    if (expression[exprPos] == 0) return exprNum;
  }
  return 0;
}


/* Emulate PROGRESS num-entries function */
/* Returns the number of items in a comma-separated list. */
long numEntries(vstring list)
{
  long i, commaCount;
  i = 0;
  commaCount = 0;
  while (list[i] != 0) {
    if (list[i] == ',') commaCount++;
    i++;
  }
  return (commaCount + 1);
}

/* Returns the character position of the start of the
   element in a list - useful for manipulating
   the list string directly.  1 means the first string
   character. */
/* If element is less than 1 or greater than number of elements
   in the list, a 0 is returned.  If entry is null, a 0 is
   returned. */
long entryPosition(long element, vstring list)
{
  long commaCount, lastComma, i;
  if (element < 1) return 0;
  lastComma = -1;
  commaCount = 0;
  i = 0;
  while (list[i] != 0) {
    if (list[i] == ',') {
      commaCount++;
      if (commaCount == element) {
        break;
      }
      lastComma = i;
    }
    i++;
  }
  if (list[i] == 0) {
    if (i == 0) return 0;
    if (list[i - 1] == ',') return 0;
    commaCount++;
  }
  if (element > commaCount) return (0);
  if (list[lastComma + 1] == ',') return 0;
  return (lastComma + 2);
}


void print2(char* fmt,...)
{
  /* This performs the same operations as printf, except that if a log file is
    open, the characters will also be printed to the log file. */
  va_list ap;
  char printBuffer[10001];

  va_start(ap, fmt);
  vsprintf(printBuffer, fmt, ap); /* Put formatted string into buffer */
  va_end(ap);

  printf("%s", printBuffer); /* Terminal */

  if (fplog != NULL) {
    fprintf(fplog, "%s", printBuffer);  /* Print to log file */
  }
  return;
}

/* Opens files with error message; opens output files with
   backup of previous version.   Mode must be "r" or "w". */
FILE *fSafeOpen(vstring fileName, vstring mode)
{
  FILE *fp;
  vstring prefix = "";
  vstring postfix = "";
  vstring bakName = "";
  vstring newBakName = "";
  long v;

  if (!strcmp(mode, "r")) {
    fp = fopen(fileName, "r");
    if (!fp) {
      print2("?Sorry, couldn't open the file \"%s\".\n", fileName);
    }
    return (fp);
  }

  if (!strcmp(mode, "w")) {
    /* See if the file already exists. */
    fp = fopen(fileName, "r");

    if (fp) {
      fclose(fp);

#define VERSIONS 9
      /* The file exists.  Rename it. */

#if defined __WATCOMC__ /* MSDOS */
      /* Make sure file name before extension is 8 chars or less */
      i = instr(1, fileName, ".");
      if (i) {
        let(&prefix, left(fileName, i - 1));
        let(&postfix, right(fileName, i));
      } else {
        let(&prefix, fileName);
        let(&postfix, "");
      }
      let(&prefix, cat(left(prefix, 5), "~", NULL));
      let(&postfix, cat("~", postfix, NULL));
      if (0) goto skip_backup; /* Prevent compiler warning */

#elif defined __GNUC__ /* Assume unix */
      let(&prefix, cat(fileName, "~", NULL));
      let(&postfix, "");

#elif defined THINK_C /* Assume Macintosh */
      let(&prefix, cat(fileName, "~", NULL));
      let(&postfix, "");

#elif defined VAXC /* Assume VMS */
      /* For debugging on VMS: */
      /* let(&prefix, cat(fileName, "-", NULL));
         let(&postfix, "-"); */
      /* Normal: */
      goto skip_backup;

#else /* Unknown; assume unix standard */
      /*if (1) goto skip_backup;*/  /* [if no backup desired] */
      let(&prefix, cat(fileName, "~", NULL));
      let(&postfix, "");

#endif


      /* See if the lowest version already exists. */
      let(&bakName, cat(prefix, str(1), postfix, NULL));
      fp = fopen(bakName, "r");
      if (fp) {
        fclose(fp);
        /* The lowest version already exists; rename all to lower versions. */

        /* If version VERSIONS exists, delete it. */
        let(&bakName, cat(prefix, str(VERSIONS), postfix, NULL));
        fp = fopen(bakName, "r");
        if (fp) {
          fclose(fp);
          remove(bakName);
        }

        for (v = VERSIONS - 1; v >= 1; v--) {
          let(&bakName, cat(prefix, str(v), postfix, NULL));
          fp = fopen(bakName, "r");
          if (!fp) continue;
          fclose(fp);
          let(&newBakName, cat(prefix, str(v + 1), postfix, NULL));
          rename(bakName, newBakName);
        }

      }
      let(&bakName, cat(prefix, str(1), postfix, NULL));
      rename(fileName, bakName);

      /***
      printLongLine(cat("The file \"", fileName,
          "\" already exists.  The old file is being renamed to \"",
          bakName, "\".", NULL), "  ", " ");
      ***/
    } /* End if file already exists */
   /*skip_backup:*/

    fp = fopen(fileName, "w");
    if (!fp) {
      print2("?Sorry, couldn't open the file \"%s\".\n", fileName);
    }

    let(&prefix, "");
    let(&postfix, "");
    let(&bakName, "");
    let(&newBakName, "");

    return (fp);
  } /* End if mode = "w" */

  bug(1510); /* Illegal mode */
  return(NULL);

}


/* Bug check */
void bug(int bugNum)
{
  print2("?Error: Program bug # %d\n", bugNum);
  exit(0);
}
