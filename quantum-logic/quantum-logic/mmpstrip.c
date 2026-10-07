/* mmpstrip.c */
#define VERSION "0.4 22-May-2010"

/* To run this program, type:
      mmpstrip < file1 > file2
   where
      file1 = input file with MMP diagrams in Brendan McKay's format
      file2 = output file with {0,1} state existence information
   See  mmpstrip --help  for more options and explanation.
*/

/*****************************************************************************/
/*       Copyright (C) 2010  NORMAN D. MEGILL  <nm at alum.mit.edu>          */
/*             License terms:  GNU General Public License                    */
/*****************************************************************************/


#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <limits.h>
#include <unistd.h>  /* For getpid; not part of C standard */

/***********************************************************************/
/************ Start of "vstring" header stuff **************************/
/************ Do not touch anything in this section ********************/
/***********************************************************************/
typedef char* vstring;

/* String assignment - MUST be used to assign vstrings */
void let(vstring *target,vstring source);
/* String concatenation - last argument MUST be NULL */
vstring cat(vstring string1,...);

/* Emulate BASIC linput statement; returns NULL if EOF */
/* Note that linput assigns target string with let(&target,...) */
  /*
    BASIC:  linput "what";a$
    c:      linput(NULL,"what?",&a);

    BASIC:  linput #1,a$                        (error trap on EOF)
    c:      if (!linput(file1,NULL,&a)) break;  (break on EOF)

  */
vstring linput(FILE *stream,vstring ask,vstring *target);

/* Emulation of BASIC string functions */
vstring seg(vstring sin, long p1, long p2);
vstring mid(vstring sin, long p, long l);
vstring left(vstring sin, long n);
vstring right(vstring sin, long n);
vstring edit(vstring sin, long control);
vstring space(long n);
vstring string(long n, char c);
vstring chr(long n);
vstring xlate(vstring sin, vstring control);
vstring date(void);
vstring time_(void);
vstring num(double long x);
vstring num1(double long x);
vstring str(double long x);
long len(vstring s);
long instr(long start, vstring sin, vstring s);
long ascii_(vstring c);
double long val(vstring s);
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
/* Bug check error */
void bug(int bugNum);
/* End of functions you should call directly */


/* Do not call the ones below directly */
/******* Special pupose routines for better
      memory allocation (use with caution) *******/
/* Make string have temporary allocation to be released by next let() */
/* Warning:  after makeTempAlloc() is called, the vstring may NOT be
   assigned again with let() */
void makeTempAlloc(vstring s);   /* Make string have temporary allocation to be
                                    released by next let() */
/* Remaining prototypes (outside of mmvstr.h) */
char *tempAlloc(long size);     /* String memory allocation/deallocation */

#define MAX_ALLOC_STACK 100
int tempAllocStackTop=0;        /* Top of stack for tempAlloc functon */
int startTempAllocStack=0;      /* Where to start freeing temporary allocation
                                    when let() is called (normally 0, except in
                                    special nested vstring functions) */
char *tempAllocStack[MAX_ALLOC_STACK];


/*****************************************************************************/
/*********************** End of "vstring" header stuff ***********************/
/*****************************************************************************/

/* Constants */

/* Mapping for MMP diagram atoms */
#define ATOM_MAP "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs" \
    "tuvwxyz!\"#$%&'()*-/:;<=>?@[\\]^_`{|}~"
/* Maximum number of atoms - increase as needed, at expense of memory */
#define MAX_ATOMS 1000
/* Maximum number of blocks - increase as needed, at expense of memory */
#define MAX_BLOCKS 200
/* Minimum block size */
#define MIN_BLOCK_SIZE 2
/* Maximum block size - increase as needed, at expense of memory */
#define MAX_BLOCK_SIZE 10

/* Global variables */
char oneLineDisplay = 0;
char verboseMode = 0;
char noErrorCheck = 0;
long lattices = 0;
long atomMapLen;
long block[MAX_BLOCKS + 1][MAX_BLOCK_SIZE + 1];
long blockSize[MAX_BLOCKS + 1];
long blocks;
long atoms;
/* char unconnectedBlockFlag = 0; */ /* Has isolated block(s) */
char unconnectedFlag = 0;  /* Graph isn't connected (two or more sections) */
long double unconnectedSkippedCountFloat = 0;
char userNormalize = 1; /* Normalize output by default */


/* Prototypes */
vstring parseMMP(vstring inputDiagram, char normalize);
long nextCombo(vstring combo, long slots);
long double choose(unsigned n, unsigned k);
void shuffle(long *card, long cards);
unsigned long getSeed(void);
unsigned long mix3(unsigned long a, unsigned long b, unsigned long c);
long **alloc2DMatrix(long xsize, long ysize);
void free2DMatrix(long **matrix, long xsize, long ysize);




/******************** Main program *******************************************/

int main(int argc, char *argv[])
{

  /* Integer variable declarations */

  /* This is how you declare some strings you want to work with */
  /* They MUST be initialized to the empty string, never to anything else */
  vstring str1 = "";
  vstring str2 = "";
  long i, j, k, p;
  char found;
  long arg;

  /* To save the starting diagram that we'll extract subsets from */
  long masterBlock[MAX_BLOCKS + 1][MAX_BLOCK_SIZE + 1];
  long masterBlockSize[MAX_BLOCKS + 1];
  long masterBlocks;
  long masterAtoms;

  /* To save the reference diagram for the -b-n "add blocks" feature */
  long refBlock[MAX_BLOCKS + 1][MAX_BLOCK_SIZE + 1];
  long refBlockSize[MAX_BLOCKS + 1];
  long refBlocks = 0;
  long refAtoms = 0;
  char refBlockUsed[MAX_BLOCKS + 1];
  long addedBlockToRefBlockMap[MAX_BLOCKS + 1];

  /* For the subdiagrams */
  long removedBlocks;
  long newSize;
  vstring newMMP = "";
  vstring comboString = "";
  long comboStringLen;
  char countOnly = 0;
  char countActualOnly = 0;
  char countStatistics = 0;
  long **blockAtomCount = NULL;  /* 2d matrix for use with countStatistics */
  long double totalCountFloat = 0;
  long double totalOutputFloat = 0;
  long double userStartFloat = 0;
  long double userEndFloat = 0;
  long double userIncrFloat = 0;
  long double incrNumFloat = 0;
  /*
  long totalCount = 0;
  long totalOutput = 0;
  long userStart = 0;
  long userEnd = 0;
  long userIncr = 0;
  long incrNum = 0;
  */

  char userRandom = 0;
  long randomMap[MAX_BLOCKS + 1];
  long randomSeed;
  char userShuffleOnlyMode = 0; /* Just shuffle, don't cycle thru combos */

  char userIgnoreUnconnected = 0;

  vstring refFile = ""; /* For -b-n "add blocks" feature */
  FILE *fref = NULL;    /* File handle for refFile */
  vstring refMMP = "";  /* Reference diagram for -b-n "add blocks" feature */

  char fileMode = 0;
  long fileNum = 0;
  long linesPerFile = 0;
  long lineNumInCurrentFile = 0;
  FILE *fpOutFile = NULL;
  vstring fileName = "";

  /* The largest long double that seems to work with +1 is
     2^53-1 = 9007199254740991 (9 quadrillion) */


  /* if (strlen(ATOM_MAP) != MAX_ATOMS) bug(1); */
  atomMapLen = strlen(ATOM_MAP); /* Do here to speed up its reuse */


  removedBlocks = 1; /* Default */

  for (arg = 1; arg < argc; arg++) {
    let(&str1, ""); /* Purge left(), right() vstring function alloc. */
    if (!strcmp(left(argv[arg], 2), "-b")) {
      let(&str1, right(argv[arg], 3));
      i = instr(1, str1, "-");
      if (i) {
        /* Parse a simple subtraction operation */
        removedBlocks = val(left(str1, i - 1)) - val(right(str1, i + 1));
      } else {
        removedBlocks = val(str1);
      }
      /* -b0 means just renormalize input file; -b-n means add 1 block
         from reference file -rf */
      if (str1[0] == 0) {
        fprintf(stderr,
            "?Error: <blocks> must be specified in \"-b<blocks>\"\n");
        exit(1);
      }
      /* (Any number now allowed)
      if (removedBlocks < -1 || str1[0] == 0) {
        fprintf(stderr,
            "?Error: <blocks> must be -1 or greater in \"-b<blocks>\"\n");
        exit(1);
      }
      */
    } else if (!strcmp(left(argv[arg], 3), "-rf")) {
      if (!strcmp(left(argv[arg], 4), "-rf=")) {
        let(&str1, right(argv[arg], 5));
      } else {
        fprintf(stderr,
            "?Error: use \"-rf=<filename>\" (no space)\n");
        exit(1);
      }
      let(&refFile, str1);
    } else if (!strcmp(left(argv[arg], 2), "-s")) {
      let(&str1, right(argv[arg], 3));
      if (instr(1, str1, "*") != 0) {
        fprintf(stderr, "?Error:  use \"x\", not \"*\", for multiplication\n");
        exit(0);
      }
      i = instr(1, str1, "x");
      if (i) {
        /* Parse a simple multiplication operation */
        /* "x" is used instead of "*" to prevent shell interpretation */
        userStartFloat = val(left(str1, i - 1)) * val(right(str1, i + 1));
      } else {
        userStartFloat = val(str1);
      }
      if (userStartFloat <= 0) {
        fprintf(stderr, "?Error: <start> must be 1 or greater in \"-s<start>\"\n");
        exit(1);
      }
    } else if (!strcmp(left(argv[arg], 2), "-e")) {
      let(&str1, right(argv[arg], 3));
      if (instr(1, str1, "*") != 0) {
        fprintf(stderr, "?Error:  use \"x\", not \"*\", for multiplication\n");
        exit(0);
      }
      i = instr(1, str1, "x");
      if (i) {
        /* Parse a simple multiplication operation */
        /* "x" is used instead of "*" to prevent shell interpretation */
        userEndFloat = val(left(str1, i - 1)) * val(right(str1, i + 1));
      } else {
        userEndFloat = val(str1);
      }
      if (userEndFloat <= 0) {
        fprintf(stderr, "?Error: <end> must be 1 or greater in \"-e<end>\"\n");
        exit(1);
      }
    } else if (!strcmp(left(argv[arg], 2), "-i")) {
      let(&str1, right(argv[arg], 3));
      userIncrFloat = val(str1);
      /* userIncr = val(str1); */ /* Use integer version for -f tag */
      if (userIncrFloat < 0) {
        fprintf(stderr,
             "?Error: <incr> must 0 or greater in \"-i<incr>\"\n");
        exit(1);
      }
      if (userIncrFloat == 0) {
        userShuffleOnlyMode = 1;  /* See --help */
      }
    } else if (!strcmp(left(argv[arg], 2), "-r") && (argv[arg])[2] != 'f') {
      userRandom = 1;
      let(&str1, right(argv[arg], 3));
      if (str1[0]) {
        randomSeed = val(str1);
      } else {
        randomSeed = getSeed();
      }
      fprintf(stderr, "Seed for pseudo-random number generator = %lu\n",
          randomSeed);
      if (randomSeed < 0 || randomSeed > RAND_MAX) {
        fprintf(stderr, "?Error: random seed must be 0 through %lu\n",
            (unsigned long)RAND_MAX);
        exit(1);
      }
      srand(randomSeed);
    } else if (!strcmp(argv[arg], "-u")) {
      userIgnoreUnconnected = 1;
    } else if (!strcmp(argv[arg], "-n")) {
      userNormalize = 0;  /* Turn off normalization of output */
    } else if (!strcmp(left(argv[arg], 2), "-f")) {
      let(&str1, right(argv[arg], 3));
      fileMode = 1;
      linesPerFile = val(str1);
      if (linesPerFile <= 0) {
        fprintf(stderr, "?Error: <lines> must be 1 or greater in \"-e<end>\"\n");
        exit(1);
      }
    } else if (!strcmp(left(argv[arg], 2), "-c")) {
      let(&str1, right(argv[arg], 3));
      switch (str1[0]) {
        case 0:   /* Assume -c1 if just -c specified */
        case '1':
          countOnly = 1;
          break;
        case '2':
          countActualOnly = 1;
          break;
        case '3':
          countActualOnly = 1;
          countStatistics = 1;
          break;
        default:
          fprintf(stderr, "?Error: -c must be followed by 1, 2, or 3.\n");
          exit(1);
      }
    } else if (!strcmp(argv[arg], "--help")) {
printf("mmpstrip.c  Version %s\n", VERSION);
printf("To run this program, type:\n");
printf(
"   mmpstrip [-b#] [-rf=file] [-s#] [-e#] [-i#] [-f#] [-u] [-n]\n");
printf(
"       [-c] [-d] < file1 > file2\n");
printf("where:\n");
printf(
"   -b<blocks> = remove all combinations of <blocks> blocks from each\n");
printf(
"       input MMP diagram. If -b is not not specified, <blocks> defaults\n");
printf(
"       to 1.  A simple subtraction operation  (with no spaces) may be\n");
printf(
"       present in <blocks>; for example, -b75-20 is the same as -b55.\n");
printf(
"       SPECIAL FEATURE:  -b-<blocks> (note the minus sign before\n");
printf(
"       <blocks>) will _add_, to each input diagram, all combinations\n");
printf(
"       of <blocks> blocks taken from a reference diagram (specified\n");
printf(
"       by -rf).\n");
printf(
"   -rf=<reffile> = use <reffile> as the reference file from which to\n");
printf(
"       choose blocks to add for the -b-1 \"add one block\" feature.\n");
printf(
"       Only those blocks not in the input diagram will be used.  For\n");
printf(
"       example, if <reffile> has 75 blocks and the input diagram has 10\n");
printf(
"       blocks, then 65 11-block diagrams will be generated for that\n");
printf(
"       input diagram.  Each input diagram must be a proper subset of\n");
printf(
"       the blocks in <reffile>.  (This can be accomplished with the\n");
printf(
"       -ss option of subgraphs.c.)  If <reffile> has more than one line,\n");
printf(
"       only the first one is used.\n");
printf(
"   -s<start> = start at <start>th output line.\n");
printf(
"       If not specified, defaults to 1 (first line).  SPECIAL FEATURE:\n");
printf(
"       A simple multiplication operation (with no spaces) may be present\n");
printf(
"       in <end>; for example, -s1000x22.67 is the same as -s22670.\n");
printf(
"       (x is used instead of * to prevent shell interpretation.)\n");
printf(
"   -e<end> = end at <end>th output line.\n");
printf(
"       If not specified, defaults to the last output line.  SPECIAL\n");
printf(
"       FEATURE: A simple multiplication operation may be present; see -s.\n");
printf(
"   -i<incr> = output only every <incr>th line, starting with line 1\n");
printf(
"       (or line <start> if -s is specified).  Defaults to 1.\n");
printf(
"       May be non-integer, e.g. 3.14159.  SPECIAL FEATURE:  if <incr>\n");
printf(
"       is 0, and -e and -r are specified, then random (but possibly\n");
printf(
"       repeating) block removal combinations will be made until an output\n");
printf(
"       until the -e'th line is reached.  This is useful when choose[n,k]\n");
printf(
"       is so large that it takes too long to run through the combinations.\n");
printf(
"       Note that -i0 will process ONLY the first input line.\n");
printf(
"   -r<seed> = Randomize the combinations for removed blocks.\n");
printf(
"       The <seed> may be from 0 to %lu inclusive.  If <seed> is omitted,\n",
    (unsigned long)RAND_MAX);
printf(
"       a random seed will be used.\n");
printf(
"   -f<lines> = produce separate output files called a-#-#-#-#-#-#-#,\n");
printf(
"       where #s are the -b, -s, -e, -i, -f, and -u (0 = omitted)\n");
printf(
"       arguments, then sequence number, respectively.  Each file\n");
printf(
"       has <lines> lines (although the last file may have less if\n");
printf(
"       lines are exhausted).\n");
printf(
"   -u = suppress output lines with unconnected diagrams.  Note: the total\n");
printf(
"       count of suppressed diagrams is shown only in -f mode (so as not\n");
printf(
"       to corrupt regular output).\n");
printf(
"   -n = _don't_ normalize (rename) atoms in output lines (useful mainly\n");
printf(
"       for debugging; there may be naming gaps)\n");
printf(
"   -c1 = show only the count of the number of output lines that will\n");
printf(
"       result in the output file.  Useful to help determine -s, -e,\n");
printf(
"       and -i.  Any -s, -e, -i, or -u is ignored in this count.\n");
/*
printf(
"       Numbers > %ld will be computed and displayed, but\n", (long)LONG_MAX);
printf(
"       may not be used as arguments of -s, -e, or -i.\n");
*/
printf(
"   -c2 = same as -c1, but take -s, -e, -i, and -u into account (slower).\n");
printf(
"   -c3 = same as -c2, but show breakdown by blocks and atoms.\n");
printf("For this help message, type:  mmpstrip --help\n");
printf("\n");
printf(
"Description:  This program outputs all subsets of the input MMPs that\n");
printf(
"have a specified number of blocks removed.  The MMP input file notation\n");
printf(
"is the same as for Greechie diagrams described in the help for the\n");
printf(
"program latticeg.c\n");
printf("\n");
printf("Example of use:\n");
printf("  ./mmpstrip -b1 < test.o\n");
printf("where test.o contains the line:\n");
printf("  1234,4567,789.\n");
printf("The output file will have 3 lines:\n");
printf("  4567,789.\n");
printf("  1234,789.\n");
printf("  1234,4567.\n");
/*
printf("  #1.1: 4567,789.\n");
printf("  #1.2: 1234,789.\n");
printf("  #1.3: 1234,4567.\n");
printf("The output MMP has atoms renumbered starting at 1 from left to\n");
printf("right.\n");
*/
      goto return_point;
    } else {
      fprintf(stderr,
"?Error:  Unrecognized option \"%s\".  Type \"mmpstrip --help\" for usage\n",
          argv[arg]);
      exit(1);
    }
  }


  /* Process the -b-1 "add one block" option */
  if (removedBlocks < 0 && refFile[0] == 0) {
    fprintf(stderr,
        "?Error: -rf=<reffile> must be specified for -b-1 feature.\n");
    exit(1);
  }
  if (refFile[0] != 0) {
    if (removedBlocks >= 0) {
      fprintf(stderr,
          "?Warning: -rf is ignored unless <blocks>=-1 in -b<blocks>.\n");
      exit(1);
    }
    /* Take file with reference diagram from field after "-rf=" */
    fref = fopen(refFile, "r");
    if (fref == NULL) {
      fprintf(stderr,
          "?File \"%s\" could not be found or opened.\n", refFile);
      exit(1);
    }
    if (linput(fref, NULL, &refMMP) == NULL) {
      fprintf(stderr,
          "?File \"%s\" is empty.\n", refFile);
      exit(1);
    }
    let(&str2, "");
    str2 = parseMMP(refMMP, 0 /* Don't normalize */);
    /* Save the reference diagram */
    refBlocks = blocks;
    refAtoms = atoms;
    for (i = 1; i <= refBlocks; i++) {
      refBlockSize[i] = blockSize[i];
      for (j = 1; j <= refBlockSize[i]; j++) {
        refBlock[i][j] = block[i][j];
      }
    }
  }


  if (userEndFloat != 0 && userEndFloat < userStartFloat) {
    fprintf(stderr,
        "?Error: <end> must not be less than <start> in \"-e<end>\"\n");
    exit(1);
  }
  if (countOnly && countActualOnly) {
    fprintf(stderr, "?Error:  Only one of -c or -d may be specified.\n");
    exit(1);
  }
  if (userShuffleOnlyMode && (userEndFloat == 0 || !userRandom)) {
    fprintf(stderr,
        "?Error: <incr> cannot be 0 in -i unless -e and -r are specified.\n");
    exit(1);
  }



  if (countStatistics) {
    if (removedBlocks != 0) {
      printf("Warning: if you want input file statistics, use -b0\n");
    }
    /* Allocate count array for maximum possible blocks and atoms, since
       we don't know how large it will be (to save reading input file
       twice) */
    blockAtomCount = alloc2DMatrix(MAX_BLOCKS + 1, MAX_ATOMS + 1);
    for (i = 0; i <= MAX_BLOCKS; i++) {
      for (j = 0; j <= MAX_ATOMS; j++) {
        blockAtomCount[i][j] = 0;
      }
    }
  }

  while (1) {
    /*
    if (totalCount == LONG_MAX) {
    */
    /* With aravind.o, the first error occurs at -b24,
              25778699578994555702 (incorrect) vs.
              25778699578994555700 (correct)
       The largest number is at -b37,
              3446310324346630677248 (incorrect) vs.
              3446310324346630677300 (correct) */
    if (totalCountFloat > 9007199254740990.0 /* 9007199254740991 */) {
      fprintf(stderr,
          "Warning:  Integer is too large (%0.0Lf > 9007199254740990);\n",
          totalCountFloat);
      fprintf(stderr,
          "  a floating-point approximation is being used.\n");
      break;
    }

    /* Get line from standard input */
    if (linput(NULL, NULL, &str1) == NULL) break; /* NULL means EOF */
    /* Clean off carriage return (for Windows files under Cygwin) and spaces */
    let(&str1, edit(str1, 2 + 4));
    lattices++;

    let(&str2, "");
    str2 = parseMMP(str1, 0 /* Don't normalize */);
    /* Save the input diagram */
    masterBlocks = blocks;
    masterAtoms = atoms;
    for (i = 1; i <= masterBlocks; i++) {
      masterBlockSize[i] = blockSize[i];
      for (j = 1; j <= masterBlockSize[i]; j++) {
        masterBlock[i][j] = block[i][j];
      }
    }

    if (removedBlocks >= 0) {
      if (removedBlocks >= masterBlocks) {
        fprintf(stderr,
          "?The number of blocks removed must be less than diagram blocks.\n");
        exit(1);
      }
      /* Initialize the combination template */
      comboStringLen = masterBlocks;
      let(&comboString, string(comboStringLen, '.'));
      /* Here we put the template to the last blocks-1 case */
      for (i = 1; i <= removedBlocks - 1; i++) {
        comboString[comboStringLen - i] = '1';
      }
      if (removedBlocks == 0) {
        /* 0 means that we are just outputting the input file (with
           renormalized lines if -n is not specified) */
        /* Set to last combination (all 1's) so 0th combination (all dots)
           will occur on the first nextCombo() call */
        let(&comboString, string(comboStringLen, '1'));
      }
    } else { /* removedBlocks < 0 */
      /* Processing for "add blocks" mode */
      comboStringLen = refBlocks - masterBlocks;
      let(&comboString, string(comboStringLen, '.'));
      if (comboStringLen < -removedBlocks) {
        fprintf(stderr,
           "?The input diagram must be a proper subset of the reference.\n");
        exit(1);
      }
      /* Here we put the template to the last blocks-1 case */
      for (i = 1; i <= -removedBlocks - 1; i++) {
        comboString[comboStringLen - i] = '1';
      }

      /* Find the subset of the refMMP corresponding to the input diagram */
      for (i = 1; i <= refBlocks; i++) refBlockUsed[i] = 0;  /* Init */
      p = 0; /* Redundant; prevent "might be used uninitialized" gcc warning */
      found = 0; /* Redundant; prevent gcc warning */
      for (i = 1; i <= masterBlocks; i++) {  /* Scan input diagram */
        for (j = 1; j <= refBlocks; j++) {   /* Scan ref diagram */
          found = 1;
          if (masterBlockSize[i] != refBlockSize[j]) {
            found = 0;
            break;
          }
          for (k = 1; k <= masterBlockSize[i]; k++) {
            if (masterBlock[i][k] != refBlock[j][k]) {
              found = 0;
              break;
            }
          }
          if (found) {
            p = j; /* The pth ref block = the ith inp block */
            break;
          }
        }
        if (!found) {
          fprintf(stderr,
             "?The input diagram is not a subset of the reference.\n");
          exit(1);
        }
        refBlockUsed[p] = 1;
      } /* next i */
      /* Populate the added block map to available ref blocks */
      p = 0;
      for (i = 1; i <= comboStringLen; i++) {
        found = 0;
        for (j = p + 1; j <= refBlocks; j++) {
          if (!refBlockUsed[j]) {
            p = j;
            addedBlockToRefBlockMap[i] = p;
            found = 1;
            break;
          }
        }
        if (!found) bug(2);
      }
    }  /* else removedBlocks < 0 */


    if (userShuffleOnlyMode) {
      /* Get to the first combination with removedBlocks removed, since
         we won't be calling nextCombo any more */
      i = nextCombo(comboString, comboStringLen);
      if (removedBlocks >= 0) {
        if (i != removedBlocks) bug(3);
      } else {
        if (i != -removedBlocks) bug(4);
      }
    }

    /* Process the "count only" option (the -c, not the -d) */
    if (countOnly) {
      /*
      while (1) {
        if (nextCombo(comboString, masterBlocks) != removedBlocks) break;
        totalCount++;
      }
      fprintf(stderr, "Counting directly: %ld\n", totalCount);
      */
      if (removedBlocks >= 0) {
        totalCountFloat += choose(comboStringLen, removedBlocks);
      } else {
        totalCountFloat += choose(comboStringLen, -removedBlocks);
      }
      continue;
    }

    /* Initialize the map used for -r */
    for (i = 1; i <= comboStringLen; i++) {
       /* For normal use, map is transparent (identity map) */
       randomMap[i] = i;
    }
    /* For userIncr (-i) > 0, this is the (only) random shuffle for
       the input diagram.  If userIncr = 1 all combinations will still
       be chosen so userRandom has no effect (except the output lines will
       be in random order).  If userIncr > 1, combinations will be skipped,
       but "randomly" instead of periodically.
       for userIncr = 0 (userShuffleOnlyMode), a random shuffle is done
       before each output line is picked, so this shuffle() call is
       redundant in that case. */
    if (userRandom) shuffle(randomMap, comboStringLen);



    /* Reconstruct an MMP diagram for each subset with blocks removed */
    while(1) {
      if (userEndFloat != 0 && totalCountFloat >= userEndFloat)
        break; /* Done */
      if (!userShuffleOnlyMode) {
        if (removedBlocks >= 0) {
          if (nextCombo(comboString, comboStringLen) != removedBlocks) break;
                                               /* Exhausted combinations */
        } else {
          if (nextCombo(comboString, comboStringLen) != -removedBlocks) break;
                                               /* Exhausted combinations */
        }
      } else {
        /* We leave the comboString at a fixed value, and instead shuffle
           the randomMap over and over each pass.  The passes will continue
           until the -e parameter lines are output.  Only the first input
           line will be used. */
        shuffle(randomMap, comboStringLen);
      }
      totalCountFloat++;
      /* if (totalCount == LONG_MAX) break; */ /* Integer overflow */
      if (userStartFloat > totalCountFloat) continue; /* Not yet at userStart */
      if (userIncrFloat != 0) {
        if (totalCountFloat -
               (userStartFloat != 0 ? (userStartFloat - 1) : 0) - 1
            < incrNumFloat * userIncrFloat) {
          continue;
        }
        incrNumFloat++;
      }
      /* old
      if (userIncr != 0 &&
            totalCount - (userStart != 0 ? (userStart - 1) : 0) - 1 !=
          ((totalCount - (userStart != 0 ? (userStart - 1) : 0) - 1)
              / userIncr ) * userIncr) continue;
      if (userEnd != 0 && userEnd < totalCount) break;
      */

      newSize = 0;
      if (removedBlocks >= 0) {
        for (j = 1; j <= masterBlocks; j++) {
          if (comboString[randomMap[j] - 1] != '1') {
            /* '1' means "remove block" */
            newSize = newSize + masterBlockSize[j] + 1;
          }
        }
      } else {
        for (j = 1; j <= masterBlocks; j++) {
          newSize = newSize + masterBlockSize[j] + 1;
        }
        for (j = 1; j <= comboStringLen; j++) {
          if (comboString[randomMap[j] - 1] == '1') {
            /* '1' means "add block" */
            newSize = newSize + refBlockSize[addedBlockToRefBlockMap[j]] + 1;
          }
        }
      }
      /* Note: extended notation is NOT accounted for here! */
      let(&newMMP, space(newSize));
      p = 0;
      if (removedBlocks >= 0) {
        for (j = 1; j <= comboStringLen; j++) {
          if (comboString[randomMap[j] - 1] != '1') {
            for (k = 1; k <= masterBlockSize[j]; k++) {
              if (newMMP[p] != ' ') bug(5);
              newMMP[p] = ATOM_MAP[masterBlock[j][k] - 1];
              p++;
            }
            if (newMMP[p] != ' ') bug(6);
            newMMP[p] = ',';
            p++;
          }
        }
      } else { /* removedBlocks < 0 */
        for (j = 1; j <= masterBlocks; j++) {
          for (k = 1; k <= masterBlockSize[j]; k++) {
            if (newMMP[p] != ' ') bug(7);
            newMMP[p] = ATOM_MAP[masterBlock[j][k] - 1];
            p++;
          }
          if (newMMP[p] != ' ') bug(8);
          newMMP[p] = ',';
          p++;
        }
        for (j = 1; j <= comboStringLen; j++) {
          if (comboString[randomMap[j] - 1] == '1') {
            /* '1' means "add block" */
            for (k = 1; k <= refBlockSize[addedBlockToRefBlockMap[j]]; k++) {
              if (newMMP[p] != ' ') bug(9);
              newMMP[p] =
                  ATOM_MAP[refBlock[addedBlockToRefBlockMap[j]][k] - 1];
              p++;
            }
            if (newMMP[p] != ' ') bug(10);
            newMMP[p] = ',';
            p++;
          }
        }
      } /* else removedBlocks < 0 */
      if (p == 0) bug(11);
      if (newMMP[p] != 0) bug(12);
      newMMP[p - 1] = '.';

      let(&str2, "");
      str2 = parseMMP(newMMP, userNormalize);

      if (countStatistics) {
        blockAtomCount[blocks][atoms]++;
      }

      /* Since we are not (in this version) renumbering atoms, the
         MMP diagram should be unchanged.  Remove this bug check if
         it is decided to renumber atoms in parseMMP (and update the
         parse to handle >127 atoms) */
      /* 6-Apr-2010 nm We are now renumbering them, so remove bugcheck. */
      /*
      if (strcmp(str2, newMMP)) {
        fprintf(stderr, "Before: %s\n", newMMP);
        fprintf(stderr, "After:  %s\n", str2);
        bug(13);
      }
      */

      /*if (unconnectedFlag) fprintf(stderr, "Has unconnected block: ");*/

      /* if (!unconnectedFlag)
        fprintf(stderr, "(%ld/%ld) %s\n", atoms, blocks, str2); */

      if (!unconnectedFlag || !userIgnoreUnconnected) {
        if (!countActualOnly) {
          if (!fileMode) {
            /* printf("#%ld.%ld: %s\n", lattices, i, str2); */
            printf("%s\n", str2);
#ifdef __STDC__
            fflush(stdout);
#endif
          } else {  /* fileMode=1 */
            /* Handle output file mode */
            if (lineNumInCurrentFile == 0) { /* 1st time, or prev. file full */
              /* Create a new output file */
              fileNum++; /* Increment file number counter */
              /* Create the output file */
              let(&fileName, cat("a-", str(removedBlocks),
                  "-", str(userStartFloat),
                  "-", str(userEndFloat), "-", str(userIncrFloat),
                  "-", str(linesPerFile),
                  "-", str(userIgnoreUnconnected ? 1 : 0),
                  "-", str(fileNum), NULL));
              fprintf(stderr, "Creating output file \"%s\"...\n", fileName);
              fpOutFile = fopen(fileName, "w");
              if (fpOutFile == NULL) {
                fprintf(stderr,
                    "?Error: couldn't create file \"%s\".\n", fileName);
                exit(1);
              }
              lineNumInCurrentFile = 1;
            }
            fprintf(fpOutFile, "%s\n", str2);
            lineNumInCurrentFile++;
            if (lineNumInCurrentFile > linesPerFile) {
              lineNumInCurrentFile = 0; /* Reset counter */
              /* Close file */
              fclose(fpOutFile);
            }
          }
        }
        totalOutputFloat++;
      } else {
        unconnectedSkippedCountFloat++;
      } /* if not unconnectedBlock */
    } /* next i */

  } /* end while 1 (scan of input file) */


  if (unconnectedSkippedCountFloat > 0) {
    fprintf(stderr,
        "%0.0Lf line(s) with unconnected diagrams were suppressed.\n",
        unconnectedSkippedCountFloat);
  }
  if (!countOnly && !countActualOnly) {
    fprintf(stderr, "%0.0Lf line(s) were output.\n", totalOutputFloat);
  }


  /* Process the -c1 option */
  if (countOnly) {
    fprintf(stderr,
"The %ld input line(s) will generate a grand total of %0.0Lf output lines.\n",
        lattices, totalCountFloat);
    if (userStartFloat != 0 || userEndFloat != 0 || userIncrFloat != 0
        || userIgnoreUnconnected) {
      fprintf(stderr,
          "(Note: -e, -s, -i, and -u parameters are ignored by -c1.)\n");
    }
  }

  /* Process the -c2 and -c3 options */
  if (countActualOnly) {
    printf(
 "The %ld input line(s) will generate a grand total of %0.0Lf output lines.\n",
        lattices, totalOutputFloat);
    if (unconnectedSkippedCountFloat > 0) {
      fprintf(stderr,
 "%0.0Lf line(s) with unconnected blocks will be suppressed.\n",
          unconnectedSkippedCountFloat);
    }
  }

  /* Process the -c3 option */
  if (countStatistics) {
    printf("Breakdown of block and atom counts in the output lines:\n");
    for (i = 1; i <= MAX_BLOCKS; i++) {
      k = 0;
      for (j = 1; j <= MAX_ATOMS; j++) {
        if (blockAtomCount[i][j] != 0) {
          k += blockAtomCount[i][j];
          printf("  %ld blocks and %ld atoms:  %ld\n", i, j,
              blockAtomCount[i][j]);
        }
      }
      if (k > 0) printf("      Total with %ld blocks:  %ld\n", i, k);
    }
    free2DMatrix(blockAtomCount, MAX_BLOCKS, MAX_ATOMS);
  }


 return_point:
  /* Deallocate vstring memory */
  let(&str1, "");
  let(&str2, "");
  let(&newMMP, "");

  return 0;
} /* End of main() */


/* Caller must deallocate returned string. */
vstring parseMMP(vstring inputDiagram /* MMP diagram */,
    char normalize /* 0=don't, 1=do normalize output diagram */) {
  long i, j, k, m, n;
  vstring jptr;
  long extendedNotationIncr; /* For + notation */
  long extendedNotationOffset; /* For + notation */
  /*vstring atomRemap = "";*/ /* To fill in atom gaps */
  long atomRemap[MAX_ATOMS + 1]; /* To fill in atom gaps */
  /*vstring inputDiagram = "";*/
  vstring str1 = "";
  vstring outputDiagram = "";

  /* extendedNotationIncr = strlen(ATOM_MAP); */ /* For + notation */
  extendedNotationIncr = atomMapLen; /*  For + notation (faster than strlen) */

  /*let(&inputDiagram, glattice);*/
  /*let(&inputDiagram, edit(glattice, 2));*/ /* Remove spaces */

  n = strlen(inputDiagram);

  if (!noErrorCheck) {
    /* The calling routine should ensure this */
    if (strchr(inputDiagram, ' ') != NULL) bug(14);

    /* inputDiagram can't be a blank line */
    if (inputDiagram[0] == 0) {
      fprintf(stderr, "#%ld: %s\n", lattices, inputDiagram);
      fprintf(stderr, "?Error: Blank lines are not allowed\n");
      exit(1);
    }

    /* inputDiagram must have ending period for new (Brendan) compact standard */
    if (inputDiagram[n - 1] != '.') {
      fprintf(stderr, "#%ld: %s\n", lattices, inputDiagram);
      fprintf(stderr, "?Error: Last character should be a period\n");
      exit(1);
    }

    /* if (instr(1, left(inputDiagram, n - 1), ".") != 0) { */
    if (strchr(inputDiagram, '.') != inputDiagram + n - 1) {
      fprintf(stderr, "#%ld: %s\n", lattices, inputDiagram);
      fprintf(stderr, "?Error: Period can only be last character\n");
      exit(1);
    }
    if (n == 1) {
      fprintf(stderr, "#%ld: %s\n", lattices, inputDiagram);
      fprintf(stderr, "?Error: Diagram must have at least one block\n");
      exit(1);
    }
  }

  atoms = 0;
  blocks = 1;
  blockSize[blocks] = 0;
  extendedNotationOffset = 0; /* For + notation */
  for (i = 0; i < n; i++) {
    if (inputDiagram[i] == ',' || inputDiagram[i] == '.') {
      /* End of block */
      if (blockSize[blocks] < MIN_BLOCK_SIZE) {
        fprintf(stderr, "#%ld: %s\n", lattices, inputDiagram);
        fprintf(stderr,
            "?Error: Block %ld has %ld atoms, but minimum block size is %ld\n",
             blocks, blockSize[blocks], (long)MIN_BLOCK_SIZE);
        exit(1);
      }
      if (inputDiagram[i] == ',') {
        /* Start of new block */
        blocks++;
        if (blocks > MAX_BLOCKS) {
          fprintf(stderr, "#%ld: %s\n", lattices, inputDiagram);
          fprintf(stderr,
   "?Error: Maximum blocks allowed is %ld.  Increase MAX_BLOCKS in program.\n",
                (long)MAX_BLOCKS);
          exit(1);
        }
        blockSize[blocks] = 0;
      }
      continue;
    }

    if (inputDiagram[i] == '+') {
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
      extendedNotationOffset += extendedNotationIncr;
      continue;
    }

    /* Get the atom number */
    /*j = instr(1, ATOM_MAP, chr(inputDiagram[i]));*/
    /*let(&str1, "");*/ /* Deallocate chr call */
    jptr = strchr(ATOM_MAP, inputDiagram[i]);
    if (jptr == NULL) {
      fprintf(stderr, "#%ld: %s\n", lattices, inputDiagram);
      fprintf(stderr, "?Error: Illegal character '%c' in diagram\n",
          inputDiagram[i]);
      exit(1);
    }
    j = jptr - ATOM_MAP + 1; /* Atom number */
    j += extendedNotationOffset; /* For + notation */
    extendedNotationOffset = 0; /* For + notation - initialize for next atom */
    blockSize[blocks]++;
    if (blockSize[blocks] > MAX_BLOCK_SIZE) {
      fprintf(stderr, "#%ld: %s\n", lattices, inputDiagram);
      fprintf(stderr,
           "?Error: Block %ld has %ld atoms, but maximum block size is %ld \n",
           blocks, blockSize[blocks], (long)MIN_BLOCK_SIZE);
      exit(1);
    }
    /* Assign the atom */
    block[blocks][blockSize[blocks]] = j;
    if (j > atoms) atoms = j; /* Maximum atom number */
  } /* next i */


  if (!noErrorCheck) {
    for (i = 1; i <= blocks; i++) {
      for (j = 1; j <= blockSize[i] - 1; j++) {
        for (k = j + 1; k <= blockSize[i]; k++) {
          if (block[i][j] == block[i][k]) {
            fprintf(stderr, "#%ld: %s\n", lattices, inputDiagram);
            fprintf(stderr,
                "?Error: Duplicate atom numbers in a block\n");
            exit(1);
          }
        }
      }
    }
  }



  /* Prevent compiler unused variable warnings due to stripped code below */
  /* let(&atomRemap, ""); */
  let(&str1, "");


  /********* Start of connectivity test *******/
  /* let(&atomRemap, string(blocks + 1, 1)); */ /*old*/  /* Re-use the
                      atomRemap string; start at ASCII 1, not 0, since 0
                      means end-of-string */
  /* (Here we are "borrowing" atomRemap[] for another purpose) */
  for (i = 1; i <= blocks; i++) atomRemap[i] = 1;
  atomRemap[1] = 2; /* 1 = not connected to 1st block; 2 = connected;
                       3 = connected and we've processed it */
  /* Starting with block one, flag all blocks connected to it, then
     connected to all flagged blocks, etc. until nothing changes */
  n = 1;
  while (n) {
    n = 0;
    for (i = 1; i <= blocks; i++) {
      if (atomRemap[i] == 2) { /* Look at blocks added to list so far */
        for (j = 1; j <= blockSize[i]; j++) {
          for (k = 1; k <= blocks; k++) {
            if (atomRemap[k] == 1) { /* Look remaining unconnected blocks */
              for (m = 1; m <= blockSize[k]; m++) {
                if (block[i][j] == block[k][m]) {
                  atomRemap[k] = 2; /* Block is connected */
                  n = 1; /* Flag that something changed */
                  break;
                }
              }
            }
          } /* next k */
        } /* next j */
        atomRemap[i] = 3; /* Flag it as processed */
      }
    } /* next i */
  } /* end while */
  unconnectedFlag = 0;  /* Global flag */
  for (i = 1; i <= blocks; i++) {
    if (atomRemap[i] < 2) {
      unconnectedFlag = 1; /* Graph isn't connected */
      break;
    }
  }
  /* let(&atomRemap, ""); */ /* Deallocate memory */
  /********* End of connectivity test *******/


  /********* Start of canonical atom renaming section *******/

  if (normalize) { /* Skip renumbering */
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
      print2("%s: %s\n", latticeName, inputDiagram);
      print2("?Error: There are gaps in atom numbering\n");
      exit(0);
    }
    */
    /***/
    /* If there are gaps, remap the atoms to fill in the gaps */
    if (n > 0) {
      /* 25-Sep-2009 This is taken from states.c, where atomRemap is
         wideString */
      /* It must be changed to wideString for > 127 (?) atoms */
      /* if (atoms >= 127) bug(15); */ /* Need to switch to wideString */
      /* 19-Apr-2010 We now use an array from atomRemap so we don't
         need the wideString stuff */
      /* (Here is the intended use of atomRemap[]) */
      /*let(&atomRemap, string(atoms + 1, '?'));*/ /*old*/
      for (i = 1; i <= atoms; i++) atomRemap[i] = '?';
      j = 0;
      for (i = 1; i <= atoms; i++) {
        if (str1[i] == '1') {
          j++; /* Atom is used */
          atomRemap[i] = j;
        }
      }
      if (atoms - j != n) bug(16); /* Sanity check */
      atoms = j; /* True number of atoms, with no gaps */
      for (i = 1; i <= blocks; i++) {
        for (j = 1; j <= blockSize[i]; j++) {
          block[i][j] = atomRemap[block[i][j]];
        }
      }
      /*let(&atomRemap, "");*/ /* Deallocate memory */
    }
    /***/
    /* Renumber the atoms starting at 1 from left to right */
    /* This will make sort | uniq find more duplicates to ignore */
    /* See wideString warning above */
    /*let(&atomRemap, string(atoms + 1, 127));*/
    for (i = 1; i <= atoms; i++) atomRemap[i] = -1; /* -1 = "not an atom" */
    k = 0;
    for (i = 1; i <= blocks; i++) {
      for (j = 1; j <= blockSize[i]; j++) {
        /* if (atomRemap[block[i][j]] == 127) { */
        if (atomRemap[block[i][j]] == -1) {
          k++;
          /* if (k == 127) bug(17); */
          atomRemap[block[i][j]] = k;
        }
        block[i][j] = atomRemap[block[i][j]];
      }
    }
    /* let(&atomRemap, ""); */
    n = 1;  /* Force the diagram to be rewritten below */
  } /* if normalize */
  /********* End of canonical atom renaming section *******/


/*
  /@ See if there are isolated blocks @/
  unconnectedBlockFlag = 0;  /@ Global flag @/
  let(&atomRemap, string(atoms + 1, 1)); /@ Start at ASCII 1, not 0; @/
               /@ otherwise, there is some weird stack dump behavior @/
  for (i = 1; i <= blocks; i++) {
    for (j = 1; j <= blockSize[i]; j++) {
      atomRemap[block[i][j]]++;  /@ Number of blocks used by this atom @/
    }
  }
  for (i = 1; i <= blocks; i++) {
    k = 0; /@ Flag that atom used by more than one block @/
    for (j = 1; j <= blockSize[i]; j++) {
      if (atomRemap[block[i][j]] > 2) {
        k = 1; /@ Atom is used by more than one block @/
        break;
      }
    }
    if (k == 0) {
      unconnectedBlockFlag = 1;
      break;
    }
  }
  let(&atomRemap, ""); /@ Deallocate memory @/
*/


  if (!normalize) n = 0; /* Skip renumbering below */

  /* This is the global greechie diagram for use wherever
     we want to print it out. */
  /* if (instr(1, inputDiagram, ".") == 0 */
  if (strchr(inputDiagram, '.') == NULL
                          /* No period - assume old standard:  3-atom blocks */
         || n > 0) {
             /* Also, if there are atom numbering gaps, rewrite the diagram. */
    /* First, compute the size of the new diagram */
    m = 0;
    for (i = 1; i <= blocks; i++) {
      for (j = 1; j <= blockSize[i]; j++) {
        k = block[i][j];
        while (k > atomMapLen) {
          /* Handle extended notation */
          m++;
          k -= atomMapLen;
        }
        m++;
      }
      m++;
    }
    let(&outputDiagram, space(m)); /* Preallocate string to computed size */
    /* Next, fill in the characters */
    m = 0;
    for (i = 1; i <= blocks; i++) {
      for (j = 1; j <= blockSize[i]; j++) {
        k = block[i][j];
        while (k > atomMapLen) {
          /* Handle extended notation */
          outputDiagram[m] = '+';
          m++;
          k -= atomMapLen;
        }
        outputDiagram[m] = ATOM_MAP[k - 1];
        m++;
      }
      if (i < blocks) {
        outputDiagram[m] = ',';
        m++;
      } else {
        outputDiagram[m] = '.';
        m++;
      }
    }
    if (outputDiagram[m] != 0) bug(18); /* Must be end of string */
  } else {
    /* It is already in the new compact form */
    let(&outputDiagram, inputDiagram);
  }

  /* Deallocate strings */
  let(&str1, "");
  /*let(&inputDiagram, "");*/

  /* The caller must deallocate outputDiagram */
  return outputDiagram;
}



long nextCombo(vstring combo, long slots)
{
  /* The characters in the combo string are modified directly. */
  /* The return parameter is the number of 1s in the new combo string,
     for use in detected when we change from m to m+1 or 0 balls i.e. exhaust
     the combinations of m balls. */
  /* To scan all  C(slots,m) combinations of m balls, initialize combo to
     slots-m+1 '.'s followed by m-1 '1's e.g. "......11" to scan 3 balls
     in 8 slots.  Before each use of combo, call nextCombo().  If the
     return value is !=m, the scan is done, and exit without using combo. */
  /* Alternately, we can initialize combo to m '1's followed by
     m '.'s.  Then call nextCombo() _after_ each use of combo, and
     when the return value is != m, exit the loop. */
  /* Note that slots _must_ = strlen(combo).  No error check is performed
     for speedup. */
  /* This function gets next combination of m balls in n slots (m<=n)
     Input = old combination, "."=no ball, "1"=ball
     Output = new combination; if done for m balls, add another ball
     Sequence cycles after 2^n passes.  Example for slots = 3:

                combo
            Input   Output
            ...     1..
            1..     .1.
            .1.     ..1
            ..1     11.
            11.     1.1
            1.1     .11
            .11     111
            111     ...
  */
  /*
     Run time:  total operations, moves, fors, ifs for complete 2^n cycle
     define o(n) { return ( 2^(n+1) + 2^n - (2*n+1)); }
     ops = o(n)
     mvs = o(n) - 2
     fors = ?
     ifs = ?
     n=1: ops=3 mvs=1 fors=4 ifs=6 total=14
     n=2: ops=7 mvs=5 fors=14 ifs=15 total=41
     n=3: ops=17 mvs=15 fors=38 ifs=34 total=104
     n=4: ops=39 mvs=37 fors=90 ifs=73 total=239
     n=5: ops=85 mvs=83 fors=198 ifs=152 total=518
     n=6: ops=179 mvs=177 fors=418 ifs=311 total=1085
     n=7: ops=369 mvs=367 fors=862 ifs=630 total=2228
     n=8: ops=751 mvs=749 fors=1754 ifs=1269 total=4523
     n=9: ops=1517 mvs=1515 fors=3542 ifs=2548 total=9122
     n=10: ops=3051 mvs=3049 fors=7122 ifs=5107 total=18329
  */

  long i, oneMark = 0, dotMark = 0, ones = 0;
  if (combo[slots] != 0) bug(19);  /* strlen(combo)!= slots */
  for (i = 0; i < slots; i++) { /* Find first '1', if any */
    if (combo[i] == '1') {
      oneMark = i + 1;
      break;
    }
  }
  for (i = oneMark; i < slots; i++) { /* Find first '.' after '1', if any */
    if (combo[i] == '.') {
      dotMark = i + 1;
      break;
    }
  }
  if (dotMark > 0) {
    for (i = 0; i < dotMark - oneMark - 1; i++) {
      combo[i] = '1';
      ones++;
    }
    for (i = dotMark - oneMark - 1; i < dotMark - 1; i++) {
      combo[i] = '.';
    }
    combo[dotMark - 1] = '1';
    ones++;
    for (i = dotMark; i < slots; i++) {
      if (combo[i] == '1') ones++;
    }
  } else { /* End of an m ball sequence */
    if (oneMark > 1) { /* Start m+1 ball sequence if m < slots */
      for (i = 0; i < slots - oneMark + 2; i++) {
        combo[i] = '1';
        ones++;
      }
      for (i = slots - oneMark + 2; i < slots; i++) {
        combo[i] = '.';
      }
    } else { /* Exhausted combinations; cycle back: 111 --> ... */
      for (i = 0; i < slots; i++) {
        combo[i] = '.';
      }
    }
  }
  return ones;
}

/* Get a binomial coefficient. */
long double choose(unsigned n, unsigned k) {
  long double accum = 1;
  unsigned i;
  if (k > n) return 0;
  if (k > n / 2) k = n-k; /* Take advantage of symmetry */
  for (i = 1; i <= k; i++) {
    accum = accum * (n - k + i) / i;
  }
  /* LONG_MAX = 2147483647 */
  /*
  if (accum > 9007199254740900.0) {
    printf("Warning:  Integer overflow (greater than 9007199254740900).\n");
    printf("The final answer below is approximate.\n");
  }
  */
  /* return accum + 0.5; */ /* avoid rounding error */
  return accum + 0.000001;
}


/* Shuffle a deck of cards, 1 through cards */
void shuffle(long *card, long cards) {
  long r, a, i;
  for (i = 1; i < cards; i++) {
    /* Get a random number from i through cards */
    r = rand() % (cards - i + 1) + i;
    if (r < 1 || r > cards) bug(20);
    /* Swap ith card with rth card */
    a = card[i];
    card[i] = card[r];
    card[r] = a;
  }
}


/* Get a random seed */
unsigned long getSeed(void) {
  unsigned long seed;
  static unsigned long offset = 0;
  seed = mix3(clock() + offset, time(NULL), getpid());
  offset++; /* Ensure a different result next time this is called */
  if (seed > RAND_MAX) seed = seed % RAND_MAX;
  if (seed > RAND_MAX || seed < 0) {
    fprintf(stderr, "seed = %lu  RAND_MAX = %lu\n",
        seed, (unsigned long)RAND_MAX);
    bug(21);
  }
  return seed;
}

/* http://www.concentric.net/~Ttwang/tech/inthash.htm
   Public domain code */
unsigned long mix3(unsigned long a, unsigned long b, unsigned long c)
{
    a = a - b;  a = a - c;  a = a ^ (c >> 13);
    b = b - c;  b = b - a;  b = b ^ (a << 8);
    c = c - a;  c = c - b;  c = c ^ (b >> 13);
    a = a - b;  a = a - c;  a = a ^ (c >> 12);
    b = b - c;  b = b - a;  b = b ^ (a << 16);
    c = c - a;  c = c - b;  c = c ^ (b >> 5);
    a = a - b;  a = a - c;  a = a ^ (c >> 3);
    b = b - c;  b = b - a;  b = b ^ (a << 10);
    c = c - a;  c = c - b;  c = c ^ (b >> 15);
    return c;
}

/* Allocate a 2-dimensional long integer matrix */
long **alloc2DMatrix(long xsize, long ysize)
{
  long **matrix;
  long i;
  matrix = malloc((xsize + 1) * sizeof(long *));
  if (matrix == NULL) {
    printf("?ERROR Out of memory\n");
    exit(-1);
  }
  for (i = 0; i <= xsize; i++) {
    matrix[i] = malloc((ysize + 1) * sizeof(long));
    if (matrix[i] == NULL) {
      printf("?ERROR Out of memory\n");
      exit(-1);
    }
  }
  return matrix;
}

/* Free a 2-dimensional long integer matrix */
void free2DMatrix(long **matrix, long xsize, long ysize)
{
  long i;
  for (i = xsize; i >= 0; i--) {
    if (matrix[i] == NULL) bug(301);
    free(matrix[i]);
  }
  if (matrix == NULL) bug(302);
  free(matrix);
  return;
}


/* Allocate a 3-dimensional character matrix */
char ***alloc3DMatrix(long xsize, long ysize, long zsize)
{
  char ***matrix;
  long i, j;
  matrix = malloc((xsize + 1) * sizeof(char **));
  if (matrix == NULL) {
    printf("?ERROR Out of memory\n");
    exit(-1);
  }
  for (i = 0; i <= xsize; i++) {
    matrix[i] = malloc((ysize + 1) * sizeof(char *));
    if (matrix[i] == NULL) {
      printf("?ERROR Out of memory\n");
      exit(-1);
    }
    for (j = 0; j <= ysize; j++) {
      matrix[i][j] = malloc((zsize + 1) * sizeof(char));
      if (matrix[i][j] == NULL) {
        printf("?ERROR Out of memory\n");
        exit(-1);
      }
    }
  }
  return matrix;
}

/* Free a 3-dimensional character matrix */
void free3DMatrix(char ***matrix, long xsize, long ysize, long zsize)
{
  long i, j;
  for (i = xsize; i >= 0; i--) {
    for (j = ysize; j >= 0; j--) {
      if (matrix[i][j] == NULL) bug(300);
      free(matrix[i][j]);
    }
    if (matrix[i] == NULL) bug(301);
    free(matrix[i]);
  }
  if (matrix == NULL) bug(302);
  free(matrix);
  return;
}


/******************* End of main program ********************************/


/***********************************************************************/
/************ Start of "vstring" body stuff ****************************/
/************ Do not touch anything from here to end of program ********/
/***********************************************************************/

/*****************************************************************************/
/*       Copyright (C) 1999  NORMAN D. MEGILL  <nm at alum.mit.edu>          */
/*             License terms:  GNU General Public License                    */
/*****************************************************************************/

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

Note that ANSI c does not allow "$" as part of an identifier
name, so the names in c have had the "$" suffix removed.

     The string arguments of the vstring functions may be either standard c
strings or vstrings (except that the first argument of the 'let(&' function
must be a vstring).  The standard c string functions may use vstrings or
vstring functions as their string arguments, as long as the vstring variable
itself (which is a char * pointer) is not modified and no attempt is made to
increase the length of a vstring.  Caution must be excercised when
assigning standard c string pointers to vstrings or the results of
vstring functions, as the memory space may be deallocated when the
'le(&t' function is next executed.  For example,

        char *stdstr; /- A standard c string pointer -/
         ...
        stdstr=left("abc",2);  /- DO NOT DO THIS -/

will assign "ab" to 'stdstr', but this assignment will be lost when the
next 'let(&' function is executed.  To be safe, use 'strcpy':

        char stdstr1[80]; /- A fixed length standard c string -/
         ...
        strcpy(stdstr1,left("abc",2));

Here, of course, the user must ensure that the string copied to 'stdstr1'
does not exceed 79 characters in length.  IT IS SAFEST NOT TO USE ANY
STANDARD C STRING FUNCTIONS WITH VSTRINGS OR VSTRING FUNCTIONS UNLESS YOU
REALLY UNDERSTAND WHAT YOU ARE DOING.

     The vstring functions ('left', 'right', 'cat', etc.) allocate temporary
memory whenever they are called.  This temporary memory is deallocated
whenever a 'let(&' assignment is made.  The user should be aware of this
when using vstring functions outside of 'let(&' assignments; for example

        for (i=0; i<10000; i++)
          print2("%s\n",left(string1,70));

will allocate another 70 bytes or so of memory each 'left' call
and eventually overflow the temporary string stack.
If necessary, dummy 'let(&' assignments can be made periodically to clear
this temporary memory:

        for (i=0; i<10000; i++)
          {
          print2("%s\n",left(string1,70));
          let(&dummy,"");
          }

It should be noted that the 'linput' function assigns its target string
with 'let(&' and thus has the same deallocation effect as 'let(&'.

************************************************************************/


vstring tempAlloc(long size)    /* String memory allocation/deallocation */
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
/* Warning:  after makeTempAlloc() is called, the genString may NOT be
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
double long val(vstring s)
{
  /*
  return (atof(s));
  */
  /* 12/10/98 - NDM - atof may corrupt memory when processing
     random character strings.
     The implementation below makes best guess of value of any
     random string, ignoring commas, etc. and tolerating numbers
     suffixed with sign.  "E" notation is not handled. */
  long double v = 0;
  char signFound = 0;
  long double power = 1.0;
  long i;
  /* Scan from lsd backwards to minimize rounding errors */
  for (i = strlen(s) - 1; i >= 0; i--) {
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
        sprintf(sout,"%d-%s-%d",
                time_structure->tm_mday,
                month[time_structure->tm_mon],
                time_structure->tm_year);
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
vstring str(double long f)
{
  /* This function converts a floating point number to a string in the */
  /* same way that %f in printf does, except that trailing zeroes after */
  /* the one after the decimal point are stripped; e.g., it returns 7 */
  /* instead of 7.000000000000000. */
  vstring s;
  long i;
  s = tempAlloc(50);
  sprintf(s, "%Lf", f);
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
vstring num1(double long f)
{
  return (str(f));
}


/* Return a number as an ASCII string surrounded by spaces */
vstring num(double long f)
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


/* Bug check */
void bug(int bugNum)
{
  /*print2("?Error: Program bug # %d\n", bugNum);*/
  fprintf(stderr, "?Error: Program bug # %d\n", bugNum);
  exit(0);
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

/***********************************************************************/
/************ End of "vstring" body stuff ******************************/
/***********************************************************************/
