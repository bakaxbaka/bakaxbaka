/* vectorfind.c */
#define VERSION "0.8 30-Mar-10"

/* To run this program, type:
      vectorfind -4d < file1 > file2
   where
      -4d (or -3d) = # of dimensions
      file1 = input file with MMP diagrams in Brendan McKay's format
      file2 = output file with vector information
   See  vectorfind --help  for more options and explanation.
*/

/* History: */
/* 0.8 30-Mar-2010 nm  Added -ph option for using phi=(1+sqr(5))/2
   components for 4d vectors */


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
vstring num(double x);
vstring num1(double x);
vstring str(double x);
long len(vstring s);
long instr(long start, vstring sin, vstring s);
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
/* Length of above string */
#define MAX_ATOMS 90
/* Maximum number of blocks */
#define MAX_BLOCKS 200
/* Minimum block size */
#define MIN_BLOCK_SIZE 2
/* Maximum block size */
#define MAX_BLOCK_SIZE 10

/* Global variables */
long dimensions = 0;
char noKick = 0;
char sqrt2Mode = 0;
char phiMode = 0;
char orthogonalBlockDisplay = 0;
char verboseMode = 0;
long backtrackLimit = 0; /* If non-zero, this is the backtrack timeout */
long lattices = 0;
long block[MAX_BLOCKS + 1][MAX_BLOCK_SIZE + 1];
long blockSize[MAX_BLOCKS + 1];
long blocks;
long atoms;
long totalBacktrackCount = 0; /* For user information */


/* Prototypes */
void parseAndTestMMPDiagram(vstring glattice);
char findVectorAssignment(long dims/* 3 or 4 */, long *backtrackCount);


/******************** Main program *******************************************/

int main(int argc, char *argv[])
{

  /* Integer variable declarations */

  /* This is how you declare some strings you want to work with */
  /* They MUST be initialized to the empty string, never to anything else */
  vstring str1 = "";
  vstring str2 = "";
  long arg;

  if (strlen(ATOM_MAP) != MAX_ATOMS) bug(1);

  for (arg = 1; arg < argc; arg++) {
    let(&str1, ""); /* Purge left(), right() vstring function alloc. */
    if (!strcmp(argv[arg], "-3d")) {
      if (dimensions != 0) {
        printf("?Error: only one of -3d or -4d may be specified\n");
        exit(1);
      }
      dimensions = 3;
    } else if (!strcmp(argv[arg], "-4d")) {
      if (dimensions != 0) {
        printf("?Error: only one of -3d or -4d may be specified\n");
        exit(1);
      }
      dimensions = 4;
    } else if (!strcmp(argv[arg], "-v")) {
      verboseMode = 1;
    } else if (!strcmp(argv[arg], "-nk")) {
      noKick = 1;
    } else if (!strcmp(argv[arg], "-s2")) {
      sqrt2Mode = 1;
    } else if (!strcmp(argv[arg], "-ph")) {
      phiMode = 1;
    } else if (!strcmp(argv[arg], "-ob")) {
      orthogonalBlockDisplay = 1;
    } else if (!strcmp(left(argv[arg], 2), "-t")) {
      /* Set backtrack timeout limit */
      let(&str1, right(argv[arg], 3));
      backtrackLimit = val(str1);
      if (strcmp(str(backtrackLimit), str1)) {
        printf("?Error: -t > 2 billion, or format error\n");
        exit(1);
      }
    } else if (!strcmp(argv[arg], "--help")) {
printf("vectorfind.c  Version %s\n", VERSION);
printf("To run this program, type:\n");
printf(
"   vectorfind [-3d] [-4d] [-nk] [-s2] [-ph] [-t{n}] [-ob] [-v] < file1 > file2\n");
printf("where:\n");
printf(
"   -3d = look for 3-dimensional vector assignment\n");
printf(
"   -4d = look for 4-dimensional vector assignment\n");
printf(
"   -nk = don't kick out (don't ignore) atoms occurring in only one block.\n");
printf(
"         Instead, (for -3d) to \"label\" those atoms that would have been\n");
printf(
"         kicked out and assign them from an extended set of vectors per\n");
printf(
"         mp/nm email of 1-Feb-04 and (for -4d) to assign them normally.\n");
printf(
"   -s2 = square root of 2 mode described in mp/nm email of 2-Feb-04.\n");
printf(
"         To achieve the goal of that email, use both -nk and -s2.\n");
printf(
"   -ph = phi = (1+sqr(5)/2 mode (for -4d only)\n");
printf(
"   -t = time limit per diagram (limit of number of backtracks).  -t should\n");
printf(
"        be followed by a positive integer less than 2 billion, with no\n");
printf(
"        space, for example -t1000000.  The output is \"timeoutnnn\"\n");
printf(
"        instead of \"pass\" or \"fail\" when this limit is exceeded.\n");
printf(
"        There is no limit if -t is not specified, and the program may run\n");
printf(
"        indefinitely (\"forever\").\n");
printf(
"   -ob = display the vectors in orthogonal blocks corresponding to the\n");
printf(
"         blocks in the MMP diagram.  The default is to display them in\n");
printf(
"         order corresponding to the atom numbering 123...ABC...abc... as\n");
printf(
"         described in mp/nm email of 27-Feb-04.\n");
printf(
"   -v = verbose mode with extra output information for debugging\n");
printf(
"   file1 = input file with MMP diagrams in Brendan McKay's format\n");
printf("   file2 = output file with vector assignment information\n");
printf("Exactly one of -3d or -4d must be specified.\n");
printf("For this help message, type:  vectorfind --help\n");
printf("\n");
printf(
"Purpose:  This program determines whether a vector assignment to atoms\n");
printf(
"in an MMP diagram is possible per mp/nm email of 17-Jan-04.  The output is\n");
printf(
"in the format specified in that email.  The MMP input file notation is the\n");
printf(
"same as for Greechie diagrams described in the help for the program\n");
printf(
"latticeg.c\n");
printf("\n");
printf("Example of use:\n");
printf("  vectorfind -4d < test.o\n");
printf("where test.o contains the two lines:\n");
printf("  1234,4567,789A,ABCD,DEFG,GHI1,35CE,29BI,68FH.\n");
printf("  1234,1A56,1789,37AB,2CDE,ACFG,8HIJ,4DHK,9EFI,BGJK.\n");
printf("corresponding to two diagrams, the first admitting a valid vector\n");
printf("assigment and the second one not admitting one.\n");
      goto return_point;
    } else {
      fprintf(stderr,
       "?Unrecognized option: \"%s\".  Type \"vectorfind --help\" for help.\n",
          argv[arg]);
      exit(1);
    }
  }

  if (dimensions == 0) {
    printf(
"?Error: You must specify -3d or -4d.  Type \"vectorfind --help\" for help.\n");
    exit(1);
  }

  if (dimensions != 4 && phiMode) {
    printf("?Error: -ph is valid only in -4d mode.");
    exit(1);
  }

  if (sqrt2Mode && phiMode) {
    printf("?Error: -s2 and -ph can't both be used.");
    exit(1);
  }

  while (1) {
    /* Get line from 1st file */
    if (linput(NULL, NULL, &str1) == NULL) break; /* NULL means EOF */
    /* Clean off carriage return (for Windows files under Cygwin) and spaces */
    let(&str1, edit(str1, 2 + 4));
    lattices++;
    parseAndTestMMPDiagram(str1);
    /*printf("%s\n", str2);*/
  }

  if (verboseMode) {
    printf("Total diagrams = %ld  Total backtrack count = %ld",
        lattices, totalBacktrackCount);
#ifdef CLOCKS_PER_SEC
    printf("  CPU time =%6.2f s", (double)((1.0 * clock())/CLOCKS_PER_SEC));
#endif
    printf("\n");
  }

 return_point:
  /* Deallocate vstring memory */
  let(&str1, "");
  let(&str2, "");

  return 0;
} /* End of main() */


void parseAndTestMMPDiagram(vstring glattice1) {
  long i, j, k, n;
  /*vstring glattice1 = "";*/
  long backtrackCount = 0; /* Returned statistic from state01Test */
  char result; /* Returned value of findVectorAssignment */

  /*let(&glattice1, glattice);*/
  /*let(&glattice1, edit(glattice, 2));*/ /* Remove spaces */

  if (verboseMode) printf("#%ld %s\n", lattices, glattice1);

  n = strlen(glattice1);

  if (n == n) {  /* Always do error checking */
    /* The calling routine should ensure this */
    if (strchr(glattice1, ' ') != NULL) bug(2);

    /* glattice1 has period - assume new (Brendan) compact standard */
    if (glattice1[0] == '+') {
      fprintf(stderr, "#%ld: %s\n", lattices, glattice1);
      fprintf(stderr,
          "?Error: '+' notation for large diagrams is not implemented\n");
      exit(1);
    }
    if (glattice1[n - 1] != '.') {
      fprintf(stderr, "#%ld: %s\n", lattices, glattice1);
      fprintf(stderr, "?Error: Last character should be a period\n");
      exit(1);
    }

    /* if (instr(1, left(glattice1, n - 1), ".") != 0) { */
    if (strchr(glattice1, '.') != glattice1 + n - 1) {
      fprintf(stderr, "#%ld: %s\n", lattices, glattice1);
      fprintf(stderr, "?Error: Period can only be last character\n");
      exit(1);
    }
    if (n == 1) {
      fprintf(stderr, "#%ld: %s\n", lattices, glattice1);
      fprintf(stderr, "?Error: Diagram must have at least one block\n");
      exit(1);
    }
  }

  atoms = 0;
  blocks = 1;
  blockSize[blocks] = 0;
  for (i = 0; i < n; i++) {
    if (glattice1[i] == ',' || glattice1[i] == '.') {
      /* End of block */
      if (blockSize[blocks] < MIN_BLOCK_SIZE) {
        fprintf(stderr, "#%ld: %s\n", lattices, glattice1);
        fprintf(stderr, "?Error: Minimum block size is %ld\n",
            (long)MIN_BLOCK_SIZE);
        exit(1);
      }
      if (glattice1[i] == ',') {
        /* Start of new block */
        blocks++;
        if (blocks > MAX_BLOCKS) {
          fprintf(stderr, "#%ld: %s\n", lattices, glattice1);
          fprintf(stderr, "?Error: Maximum blocks allowed is %ld\n",
              (long)MAX_BLOCKS);
          exit(1);
        }
        blockSize[blocks] = 0;
      }
      continue;
    }
    /* Get the atom number */
    /*j = instr(1, ATOM_MAP, chr(glattice1[i]));*/
    j = strchr(ATOM_MAP, glattice1[i]) - ATOM_MAP + 1;
    if (j == 0) {
      fprintf(stderr, "#%ld: %s\n", lattices, glattice1);
      fprintf(stderr, "?Error: Illegal character '%c' in diagram\n",
          glattice1[i]);
      exit(1);
    }
    blockSize[blocks]++;
    if (blockSize[blocks] > MAX_BLOCK_SIZE) {
      fprintf(stderr, "#%ld: %s\n", lattices, glattice1);
      fprintf(stderr, "?Error: Maximum block size is %ld\n",
          (long)MAX_BLOCK_SIZE);
      exit(1);
    }
    /* Assign the atom */
    block[blocks][blockSize[blocks]] = j;
    if (j > atoms) atoms = j; /* Maximum atom number */
  } /* next i */


  if (n == n) { /* Always check for errors */
    for (i = 1; i <= blocks; i++) {
      for (j = 1; j <= blockSize[i] - 1; j++) {
        for (k = j + 1; k <= blockSize[i]; k++) {
          if (block[i][j] == block[i][k]) {
            fprintf(stderr, "#%ld: %s\n", lattices, glattice1);
            fprintf(stderr,
                "?Error: Duplicate atom numbers in a block\n");
            exit(1);
          }
        }
      }
    }
  }

  result = findVectorAssignment(dimensions, &backtrackCount);
  totalBacktrackCount += backtrackCount;
  if (!verboseMode) {
      /* #16 ((37)) passes:: 8HP,9KP,25A,23L,BCQ,5DN,7CL,9EN,67F,... */
      /*printf("#%ld %s:: %s%s\n", lattices,
          (!result[0]) ? "fails" : "passes", glattice1, result);*/
  } else {
    printf("#%ld Backtrack count = %ld\n", lattices, backtrackCount);
    if (result) {
      printf("#%ld%s\n", lattices, " Admits a valid vector assignment");
    } else {
      printf("#%ld%s\n", lattices, " Admits no valid vector assignment");
    }
  }

  /* Deallocate strings */
} /* parseMMPDiagram */


/* Returns 1 if vector assignment found or 0 otherwise. */
char findVectorAssignment(long dims/* 3 or 4 */, long *backtrackCount)
{
  /* Note: almost all arrays start at 1, not 0, since I tend to make
     fewer "off by one" errors this way, at the expense of a small amount
     of additional memory. */
  /* Global variables from above for reference:
     long block[MAX_BLOCKS + 1][MAX_BLOCK_SIZE + 1];
     long blockSize[MAX_BLOCKS + 1];
     long blocks;
     long atoms;
     long totalBacktrackCount = 0; For user information
  */
/* This is (81-1)/2=40 for 4d, (125-1)/2-7=55 for 3d */
/* The -nk option adds another 24 for 3d */
/* #define MAX_VECTORS 55 + 24 */  /* Old before -ph option */
#define MAX_VECTORS 472  /* After -ph option */
#define MAX_DIMS 4
  /* Static structures that are build once */
  static long vectors = 0;
  static long vecCoeff[MAX_VECTORS + 1][MAX_DIMS + 1];
  static long vecProd[MAX_VECTORS + 1][MAX_VECTORS + 1];
  static long unlabeledVectors;
  long minVal, maxVal, i, j, k, l, n;
  long phiTCount, phiKCount; /* For phiMode */
  char skip;
  /* Structures that are built for each diagram */
  long atomBlocks[MAX_ATOMS + 1]; /* # blocks atom occurs in */
  long goodAtoms;
  long atomNeighbors[MAX_ATOMS + 1];
  long atomNeighbor[MAX_ATOMS + 1][MAX_ATOMS + 1];
  long vecUsed[MAX_VECTORS + 1]; /* 1 if vector is assigned */
  long atomVec[MAX_ATOMS + 1]; /* Vector assigned to atom */

  long atomMap[MAX_ATOMS + 1];
  long atomReverseMap[MAX_ATOMS + 1];
  long mappedAtom, mappedNeighborAtom;

  /* Structures for "clustering" algorithm */
  /* "Common" means in common with list of mapped atoms up to that point */
  long mostNeighbors, mostCommonNeighbors, atomWithMostNeighbors;
  long commonNeighbors;

  /* Variables for main backtracking scan */
  long atomLowerNeighbors[MAX_ATOMS + 1];
  long atomLowerNeighbor[MAX_ATOMS + 1][MAX_ATOMS + 1];
  char successFlag;
  char foundFlag;
  char conflict;
  long backtrackCountx = 0; /* For informational purposes */

  long m;

  /* For phiMode (-ph) */
  long t;
  char aravindVectorsOnly;

  m = 0;

  if (dims == 3) {
    minVal = -2;
    maxVal = 2;
  } else if (dims == 4 && !phiMode) {
    minVal = -1;
    maxVal = 1;
  } else if (dims == 4 && phiMode) {
    minVal = -3;
    maxVal = 3;
  } else {
    minVal = 0;
    maxVal = 0;
    bug(3); /* Only 3 or 4 dimensions allowed */
  }

  /* Build static structures the first time this is called */
  /* The code in this section doesn't have to be as efficient since it is
     done only once */
  if (vectors == 0) {
    for (i = minVal; i <= maxVal; i++) {
      if (i < 0) continue; /* Skip negative vector */
      for (j = minVal; j <= maxVal; j++) {
        if (i == 0 && j < 0) continue; /* Skip negative vector */
        for (k = minVal; k <= maxVal; k++) {
          if (i == 0 && j == 0 && k < 0) continue; /* Skip neg vector */
          for (l = minVal; l <= maxVal; l++) {
            if (dims == 3 && l != 0) continue; /* l not used for 3d */
            if (i == 0 && j == 0 && k == 0 && l < 0) continue; /* Skip neg */
            if (i == 0 && j == 0 && k == 0 && l == 0) continue; /* Skip 0 */
            if (dims == 3) { /* Skip special cases - see 17-Jan-04 email */
              if (i == 0 && j == 0 && k == 2) continue;
              if (i == 0 && j == 2 && k == 0) continue;
              if (i == 2 && j == 0 && k == 0) continue;
              if (i == 0 && j == 2 && k == 2) continue;
              if (i == 2 && j == 0 && k == 2) continue;
              if (i == 2 && j == 2 && k == 0) continue;
              if (i == 2 && j == 2 && k == 2) continue;
            }
            if (phiMode) {
              /* Allow a maximum of 1 t component and 1 k component */
              /* This reduces vector count from 1200 to 472 */
              phiTCount = 0;  phiKCount = 0;
              if (i == -2 || i == 2) phiTCount++;
              if (j == -2 || j == 2) phiTCount++;
              if (k == -2 || k == 2) phiTCount++;
              if (l == -2 || l == 2) phiTCount++;
              if (i == -3 || i == 3) phiKCount++;
              if (j == -3 || j == 3) phiKCount++;
              if (k == -3 || k == 3) phiKCount++;
              if (l == -3 || l == 3) phiKCount++;
              if (phiTCount > 1 || phiKCount > 1) continue;
            }
            /* Now we have a valid vector; add it to vector list */
            vectors++;
            if (vectors > MAX_VECTORS) bug(4);
            vecCoeff[vectors][1] = i;
            vecCoeff[vectors][2] = j;
            vecCoeff[vectors][3] = k;
            vecCoeff[vectors][4] = l;
          } /* next l */
        } /* next k */
      } /* next j */
    } /* next i */
    /* This is the most vectors we can assign to "normal" atoms (those
       in >1 blocks) for 3d mode */
    unlabeledVectors = vectors;

    /* Exended vectors for "don't kick out" i.e. "labelling" option in 3d
       (see mp/nm email of 1-Feb-04) */
    if (dims == 3 && noKick == 1) {
      for (j = -1; j <= 1; j += 2) {
        for (k = -1; k <= 1; k += 2) {
          /* All permuations of {1,2,5} */
          vectors++;
          vecCoeff[vectors][1] = 1;
          vecCoeff[vectors][2] = 2 * j;
          vecCoeff[vectors][3] = 5 * k;
          vecCoeff[vectors][4] = 0;

          vectors++;
          vecCoeff[vectors][1] = 1;
          vecCoeff[vectors][2] = 5 * j;
          vecCoeff[vectors][3] = 2 * k;
          vecCoeff[vectors][4] = 0;

          vectors++;
          vecCoeff[vectors][1] = 2;
          vecCoeff[vectors][2] = 1 * j;
          vecCoeff[vectors][3] = 5 * k;
          vecCoeff[vectors][4] = 0;

          vectors++;
          vecCoeff[vectors][1] = 2;
          vecCoeff[vectors][2] = 5 * j;
          vecCoeff[vectors][3] = 1 * k;
          vecCoeff[vectors][4] = 0;

          vectors++;
          vecCoeff[vectors][1] = 5;
          vecCoeff[vectors][2] = 1 * j;
          vecCoeff[vectors][3] = 2 * k;
          vecCoeff[vectors][4] = 0;

          vectors++;
          vecCoeff[vectors][1] = 5;
          vecCoeff[vectors][2] = 2 * j;
          vecCoeff[vectors][3] = 1 * k;
          vecCoeff[vectors][4] = 0;
        } /* next k */
      } /* next j */
    } /* if noKick == 1 */

    /* Square root of 2 mode - remap 5 to 3 and 2 to 1000 (instead of sqrt(2))*/
    /* We will detect 1000 later to handle sqrt(2) */
    if (sqrt2Mode) {
      for (i = 1; i <= vectors; i++) {
        for (k = 1; k <= 4; k++) { /* Dimension */
          if (vecCoeff[i][k] == 5) vecCoeff[i][k] = 3;
          if (vecCoeff[i][k] == -5) vecCoeff[i][k] = -3;
          if (vecCoeff[i][k] == 2) vecCoeff[i][k] = 1000;
          if (vecCoeff[i][k] == -2) vecCoeff[i][k] = -1000;
        }
      }
    }

    /* Phi mode - remap +-2 to +-phi and +-3 to +-1/phi */
    /* phi <-> 1000   1/phi = phi-1 <-> 999 */
    if (phiMode) {
      for (i = 1; i <= vectors; i++) {
        for (k = 1; k <= 4; k++) { /* Dimension */
          if (vecCoeff[i][k] == 2) vecCoeff[i][k] = 1000;
          if (vecCoeff[i][k] == -2) vecCoeff[i][k] = -1000;
          if (vecCoeff[i][k] == 3) vecCoeff[i][k] = 999;
          if (vecCoeff[i][k] == -3) vecCoeff[i][k] = -999;
        }
      }
    }

    if ((dims == 3 && noKick == 0 && vectors != 55)
        || (dims == 3 && noKick == 1 && vectors != 79)
        || (dims == 4 && !phiMode && vectors != 40)
        || (dims == 4 && phiMode && vectors != 472)) bug(5);


    /* This is an experiment to use only the vectors in Aravind's table */
    aravindVectorsOnly = 1;
    if (phiMode && aravindVectorsOnly) {
      t = 1000; k = 999; vectors = 60;
vecCoeff[1 ][1]= 1; vecCoeff[1 ][2]= 0; vecCoeff[1 ][3]= 0; vecCoeff[1 ][4]= 0;
vecCoeff[2 ][1]= 0; vecCoeff[2 ][2]= 1; vecCoeff[2 ][3]= 0; vecCoeff[2 ][4]= 0;
vecCoeff[3 ][1]= 0; vecCoeff[3 ][2]= 0; vecCoeff[3 ][3]= 1; vecCoeff[3 ][4]= 0;
vecCoeff[4 ][1]= 0; vecCoeff[4 ][2]= 0; vecCoeff[4 ][3]= 0; vecCoeff[4 ][4]= 1;
vecCoeff[5 ][1]= 1; vecCoeff[5 ][2]= 1; vecCoeff[5 ][3]= 1; vecCoeff[5 ][4]= 1;
vecCoeff[6 ][1]=-1; vecCoeff[6 ][2]= 1; vecCoeff[6 ][3]= 1; vecCoeff[6 ][4]= 1;
vecCoeff[7 ][1]= 1; vecCoeff[7 ][2]=-1; vecCoeff[7 ][3]= 1; vecCoeff[7 ][4]= 1;
vecCoeff[8 ][1]= 1; vecCoeff[8 ][2]= 1; vecCoeff[8 ][3]=-1; vecCoeff[8 ][4]= 1;
vecCoeff[9 ][1]= 1; vecCoeff[9 ][2]= 1; vecCoeff[9 ][3]= 1; vecCoeff[9 ][4]=-1;
vecCoeff[10][1]=-1; vecCoeff[10][2]=-1; vecCoeff[10][3]= 1; vecCoeff[10][4]= 1;
vecCoeff[11][1]=-1; vecCoeff[11][2]= 1; vecCoeff[11][3]=-1; vecCoeff[11][4]= 1;
vecCoeff[12][1]=-1; vecCoeff[12][2]= 1; vecCoeff[12][3]= 1; vecCoeff[12][4]=-1;
vecCoeff[13][1]= t; vecCoeff[13][2]=-1; vecCoeff[13][3]= k; vecCoeff[13][4]= 0;
vecCoeff[14][1]=-t; vecCoeff[14][2]=-1; vecCoeff[14][3]= k; vecCoeff[14][4]= 0;
vecCoeff[15][1]= t; vecCoeff[15][2]= 1; vecCoeff[15][3]= k; vecCoeff[15][4]= 0;
vecCoeff[16][1]= t; vecCoeff[16][2]=-1; vecCoeff[16][3]=-k; vecCoeff[16][4]= 0;
vecCoeff[17][1]= t; vecCoeff[17][2]= k; vecCoeff[17][3]= 0; vecCoeff[17][4]=-1;
vecCoeff[18][1]=-t; vecCoeff[18][2]= k; vecCoeff[18][3]= 0; vecCoeff[18][4]=-1;
vecCoeff[19][1]= t; vecCoeff[19][2]=-k; vecCoeff[19][3]= 0; vecCoeff[19][4]=-1;
vecCoeff[20][1]= t; vecCoeff[20][2]= k; vecCoeff[20][3]= 0; vecCoeff[20][4]= 1;
vecCoeff[21][1]= t; vecCoeff[21][2]= 0; vecCoeff[21][3]=-1; vecCoeff[21][4]= k;
vecCoeff[22][1]=-t; vecCoeff[22][2]= 0; vecCoeff[22][3]=-1; vecCoeff[22][4]= k;
vecCoeff[23][1]= t; vecCoeff[23][2]= 0; vecCoeff[23][3]= 1; vecCoeff[23][4]= k;
vecCoeff[24][1]= t; vecCoeff[24][2]= 0; vecCoeff[24][3]=-1; vecCoeff[24][4]=-k;
vecCoeff[25][1]=-1; vecCoeff[25][2]= t; vecCoeff[25][3]= 0; vecCoeff[25][4]= k;
vecCoeff[26][1]= 1; vecCoeff[26][2]= t; vecCoeff[26][3]= 0; vecCoeff[26][4]= k;
vecCoeff[27][1]=-1; vecCoeff[27][2]=-t; vecCoeff[27][3]= 0; vecCoeff[27][4]= k;
vecCoeff[28][1]=-1; vecCoeff[28][2]= t; vecCoeff[28][3]= 0; vecCoeff[28][4]=-k;
vecCoeff[29][1]=-1; vecCoeff[29][2]= k; vecCoeff[29][3]= t; vecCoeff[29][4]= 0;
vecCoeff[30][1]= 1; vecCoeff[30][2]= k; vecCoeff[30][3]= t; vecCoeff[30][4]= 0;
vecCoeff[31][1]=-1; vecCoeff[31][2]=-k; vecCoeff[31][3]= t; vecCoeff[31][4]= 0;
vecCoeff[32][1]=-1; vecCoeff[32][2]= k; vecCoeff[32][3]=-t; vecCoeff[32][4]= 0;
vecCoeff[33][1]=-1; vecCoeff[33][2]= 0; vecCoeff[33][3]= k; vecCoeff[33][4]= t;
vecCoeff[34][1]= 1; vecCoeff[34][2]= 0; vecCoeff[34][3]= k; vecCoeff[34][4]= t;
vecCoeff[35][1]=-1; vecCoeff[35][2]= 0; vecCoeff[35][3]=-k; vecCoeff[35][4]= t;
vecCoeff[36][1]=-1; vecCoeff[36][2]= 0; vecCoeff[36][3]= k; vecCoeff[36][4]=-t;
vecCoeff[37][1]= k; vecCoeff[37][2]= t; vecCoeff[37][3]=-1; vecCoeff[37][4]= 0;
vecCoeff[38][1]=-k; vecCoeff[38][2]= t; vecCoeff[38][3]=-1; vecCoeff[38][4]= 0;
vecCoeff[39][1]= k; vecCoeff[39][2]=-t; vecCoeff[39][3]=-1; vecCoeff[39][4]= 0;
vecCoeff[40][1]= k; vecCoeff[40][2]= t; vecCoeff[40][3]= 1; vecCoeff[40][4]= 0;
vecCoeff[41][1]= k; vecCoeff[41][2]=-1; vecCoeff[41][3]= 0; vecCoeff[41][4]= t;
vecCoeff[42][1]=-k; vecCoeff[42][2]=-1; vecCoeff[42][3]= 0; vecCoeff[42][4]= t;
vecCoeff[43][1]= k; vecCoeff[43][2]= 1; vecCoeff[43][3]= 0; vecCoeff[43][4]= t;
vecCoeff[44][1]= k; vecCoeff[44][2]=-1; vecCoeff[44][3]= 0; vecCoeff[44][4]=-t;
vecCoeff[45][1]= k; vecCoeff[45][2]= 0; vecCoeff[45][3]= t; vecCoeff[45][4]=-1;
vecCoeff[46][1]=-k; vecCoeff[46][2]= 0; vecCoeff[46][3]= t; vecCoeff[46][4]=-1;
vecCoeff[47][1]= k; vecCoeff[47][2]= 0; vecCoeff[47][3]=-t; vecCoeff[47][4]=-1;
vecCoeff[48][1]= k; vecCoeff[48][2]= 0; vecCoeff[48][3]= t; vecCoeff[48][4]= 1;
vecCoeff[49][1]= 0; vecCoeff[49][2]= t; vecCoeff[49][3]= k; vecCoeff[49][4]=-1;
vecCoeff[50][1]= 0; vecCoeff[50][2]=-t; vecCoeff[50][3]= k; vecCoeff[50][4]=-1;
vecCoeff[51][1]= 0; vecCoeff[51][2]= t; vecCoeff[51][3]=-k; vecCoeff[51][4]=-1;
vecCoeff[52][1]= 0; vecCoeff[52][2]= t; vecCoeff[52][3]= k; vecCoeff[52][4]= 1;
vecCoeff[53][1]= 0; vecCoeff[53][2]=-1; vecCoeff[53][3]= t; vecCoeff[53][4]= k;
vecCoeff[54][1]= 0; vecCoeff[54][2]= 1; vecCoeff[54][3]= t; vecCoeff[54][4]= k;
vecCoeff[55][1]= 0; vecCoeff[55][2]=-1; vecCoeff[55][3]=-t; vecCoeff[55][4]= k;
vecCoeff[56][1]= 0; vecCoeff[56][2]=-1; vecCoeff[56][3]= t; vecCoeff[56][4]=-k;
vecCoeff[57][1]= 0; vecCoeff[57][2]= k; vecCoeff[57][3]=-1; vecCoeff[57][4]= t;
vecCoeff[58][1]= 0; vecCoeff[58][2]=-k; vecCoeff[58][3]=-1; vecCoeff[58][4]= t;
vecCoeff[59][1]= 0; vecCoeff[59][2]= k; vecCoeff[59][3]= 1; vecCoeff[59][4]= t;
vecCoeff[60][1]= 0; vecCoeff[60][2]= k; vecCoeff[60][3]=-1; vecCoeff[60][4]=-t;
    }


    /* Populate scalar product table */
    for (i = 1; i <= vectors; i++) {
      for (j = 1; j <= vectors; j++) {
        vecProd[i][j] = 0;
        for (k = 1; k <= 4; k++) { /* k = dimension */
          if (sqrt2Mode) {
            /* Square root of 2 mode - remap the coefficients as follows:
                 was: 0   becomes: 0
                 was: 1   becomes: 1
                 was: 2   becomes: sqrt(2)
                 was: 5   becomes: 3
               In the case of sqrt(2), use 1000 unless both are sqrt(2).
               This will cause the 1000 to cancel out when the sqrt's
               cancel, but not otherwise.  In the end we only care if
               the final product vecProd[i][j] is zero or not.
            */
            l = vecCoeff[i][k] * vecCoeff[j][k];
            /* Handle sqrt(2) squared */
            if (l == 1000000 || l == -1000000) {
              /* We squared sqrt(2), so the result is 2 */
              l = l / 500000;
            }
            vecProd[i][j] += l;
          } else if (phiMode) {
            /* For studying Aravind and Lee-Elkin, Two Noncolourable
               Configurations in Four Dimensions Illustrating the
               Kochen-Specker Theorem, J. Phys. A 31 9829--9834 (1998) */
            /* Aravind's MMP diagram:   aravind.o
              1234,1nux,1oty,1psv,1qrw,2LZm,2Mal,2NXk,2OYj,3HSh,3IRi,3JQf,3KPg,
              4DVe,4EWd,4FTc,4GUb,5ABC,5Ggu,5Jkp,5Ocw,5SVZ,6789,6Ffu,6Kjp,6Nbw,
              6RWa,7Eit,7Hkq,7Oev,7QTZ,8Dgs,8Jmn,8Mdy,8SUX,9Ghr,9Ilo,9Lcx,9PVY,
              ADht,AIjq,ANdv,APUa,BEfs,BKln,BLey,BRTY,CFir,CHmo,CMbx,CQWX,DQlw,
              DRkx,EPmw,ESjx,FPky,FSlv,GQjy,GRmv,HYdu,Hacs,IXeu,IZbs,JYbt,Jaer,
              KXct,KZdr,LUip,LWgq,MThp,MVfq,NTgo,NVin,OUfo,OWhn. */
            /* Aravind's 60 vectors:
                  1 1 0 0 0     16 t -1 -k 0  31 -1 -k t 0  46 -k 0 t -1
                  2 0 1 0 0     17 t k 0 -1   32 -1 k -t 0  47 k 0 -t -1
                  3 0 0 1 0     18 -t k 0 -1  33 -1 0 k t   48 k 0 t 1
                  4 0 0 0 1     19 t -k 0 -1  34 1 0 k t    49 0 t k -1
                  5 1 1 1 1     20 t k 0 1    35 -1 0 -k t  50 0 -t k -1
                  6 -1 1 1 1    21 t 0 -1 k   36 -1 0 k -t  51 0 t -k -1
                  7 1 -1 1 1    22 -t 0 -1 k  37 k t -1 0   52 0 t k 1
                  8 1 1 -1 1    23 t 0 1 k    38 -k t -1 0  53 0 -1 t k
                  9 1 1 1 -1    24 t 0 -1 -k  39 k -t -1 0  54 0 1 t k
                  10 -1 -1 1 1  25 -1 t 0 k   40 k t 1 0    55 0 -1 -t k
                  11 -1 1 -1 1  26 1 t 0 k    41 k -1 0 t   56 0 -1 t -k
                  12 -1 1 1 -1  27 -1 -t 0 k  42 -k -1 0 t  57 0 k -1 t
                  13 t -1 k 0   28 -1 t 0 -k  43 k 1 0 t    58 0 -k -1 t
                  14 -t -1 k 0  29 -1 k t 0   44 k -1 0 -t  59 0 k 1 t
                  15 t 1 k 0    30  1 k t 0   45 k 0 t -1   60 0 k -1 -t  */
            /* We let the number 1000 represent phi=(1+sqr(5))/2.
               Let t = phi and k = 1/t.  Then the following relations
               can be computed to hold:

                  Identity        Represented by
                  --------        --------------
                    t = phi            1000
                    k = phi-1           999
                  t^2 = 1+phi          1001
                  t*k = 1                 1
                  k^2 = 2-phi          -998

               Therefore we have the following multiplication table for
               vector components involving t and k:

                        |    0      1     -1      t     -t      k     -k
                        |    0      1     -1   1000  -1000    999   -999
               ---------+------------------------------------------------
                0     0 |    0      0      0      0      0      0      0
                1     1 |    0      1     -1   1000  -1000    999   -999
               -1    -1 |    0     -1      1  -1000   1000   -999    999
                t  1000 |    0   1000  -1000   1001  -1001      1     -1
               -t -1000 |    0  -1000   1000  -1001   1001     -1      1
                k   999 |    0    999   -999      1     -1   -998    998
               -k  -999 |    0   -999    999     -1      1    998   -998

               e.g. (t k 0 1)(0 -1 t k) = 0 +  -k  + 0 +  k  = 0
                                          0 + -999 + 0 + 999 = 0
                    (0 k 1 t)(0 -1 t k) = 0 +  -k +  0 +  t  +  tk  =/= 0
                                          0 + -999 + 0 + 999 + -998 =/= 0  */
            switch (vecCoeff[i][k]) {
              case 1000:
                switch (vecCoeff[j][k]) {
                  case 1000: l = 1001; break;
                  case -1000: l = -1001; break;
                  case 999: l = 1; break;
                  case -999: l = -1; break;
                  default: l = vecCoeff[i][k] * vecCoeff[j][k];
                }
                break;
              case -1000:
                switch (vecCoeff[j][k]) {
                  case 1000: l = -1001; break;
                  case -1000: l = 1001; break;
                  case 999: l = -1; break;
                  case -999: l = 1; break;
                  default: l = vecCoeff[i][k] * vecCoeff[j][k];
                }
                break;
              case 999:
                switch (vecCoeff[j][k]) {
                  case 1000: l = 1; break;
                  case -1000: l = -1; break;
                  case 999: l = -998; break;
                  case -999: l = 998; break;
                  default: l = vecCoeff[i][k] * vecCoeff[j][k];
                }
                break;
              case -999:
                switch (vecCoeff[j][k]) {
                  case 1000: l = -1; break;
                  case -1000: l = 1; break;
                  case 999: l = 998; break;
                  case -999: l = -998; break;
                  default: l = vecCoeff[i][k] * vecCoeff[j][k];
                }
                break;
              default: l = vecCoeff[i][k] * vecCoeff[j][k];
            }
            vecProd[i][j] += l;
          } else {  /* If no special cases */
            vecProd[i][j] += vecCoeff[i][k] * vecCoeff[j][k];
          }
        }  /* next k (dimension) */
        /*
        printf(
        "v[%ld]=(%ld,%ld,%ld,%ld) v[%ld]=(%ld,%ld,%ld,%ld) v[i].v[j]=%ld\n",
        i, vecCoeff[i][1], vecCoeff[i][2], vecCoeff[i][3], vecCoeff[i][4],
        j, vecCoeff[j][1], vecCoeff[j][2], vecCoeff[j][3], vecCoeff[j][4],
        vecProd[i][j]);
         */
      }  /* next j */
    }  /* next i */
  } /* if vectors == 0 */


  /* Count number of blocks each atom occurs in */
  for (i = 1; i <= atoms; i++) {
    atomBlocks[i] = 0;
  }
  for (i = 1; i <= blocks; i++) {
    for (j = 1; j <= blockSize[i]; j++) {
      atomBlocks[block[i][j]]++;
    }
  }

  /* Map the good atoms to atoms */
  goodAtoms = 0; /* Atoms in more than 1 block */
  for (i = 1; i <= atoms; i++) {
    atomReverseMap[i] = 0; /* Means not a good atom */
    if (atomBlocks[i] > 1 || noKick == 1) {
      goodAtoms++;
      atomMap[goodAtoms] = i;
      atomReverseMap[i] = goodAtoms;
    }
  }

  /* Build the list of neighbors for each atom */
  for (i = 1; i <= goodAtoms; i++) {
    atomNeighbors[i] = 0;
  }

  /* Populate atom neighbor lists */
  for (i = 1; i <= blocks; i++) {
    for (j = 1; j <= blockSize[i]; j++) {
      if (atomBlocks[block[i][j]] < 1) bug(6);
      if (atomBlocks[block[i][j]] == 1 && noKick == 0) continue;
                  /* Ignore atoms in only 1 block */
      mappedAtom = atomReverseMap[block[i][j]];
      if (mappedAtom < 1 || mappedAtom > goodAtoms) bug(7);
      for (k = 1; k <= blockSize[i]; k++) {
        if (j == k) continue;
        if (atomBlocks[block[i][k]] == 1 && noKick == 0) continue;
                    /* Ignore atoms in only 1 block */
        mappedNeighborAtom = atomReverseMap[block[i][k]];
        if (mappedNeighborAtom < 1 || mappedNeighborAtom > goodAtoms) bug(8);
        if (mappedAtom == mappedNeighborAtom) bug(9);
        skip = 0;
        /* Don't put a neighbor twice (necessary?) */
        for (l = 1; l <= atomNeighbors[mappedAtom]; l++) {
          if (atomNeighbor[mappedAtom][l] == mappedNeighborAtom) {
            skip = 1;
            /* Enhance this with more information later if nec. */
            if (verboseMode) printf("Found duplicate neighbor pair\n");
            /*bug(10);*/ /* Should never get here with good diagram? */
            break;
          }
        }
        if (skip) continue;
        atomNeighbors[mappedAtom]++; /* Actual number of neighbors */
        atomNeighbor[mappedAtom][atomNeighbors[mappedAtom]]
            = mappedNeighborAtom;
      }
    }
  }

  for (i = 1; i <= goodAtoms; i++) {
    /* Sort the atoms for tightest "clustering" */
    mostNeighbors = 0;
    mostCommonNeighbors = 0;
    atomWithMostNeighbors = i;
    /* Look at all remaining atoms to see which has the most neighbors in
        the list of atoms so far */
    for (j = i; j <= goodAtoms; j++) {
      commonNeighbors = 0;
      for (k = 1; k <= atomNeighbors[j]; k++) {
        if (atomNeighbor[j][k] < i) commonNeighbors++;
      }
      if (commonNeighbors > mostCommonNeighbors
          || (commonNeighbors == mostCommonNeighbors &&
              atomNeighbors[j] > mostNeighbors)) {
        mostCommonNeighbors = commonNeighbors;
        mostNeighbors = atomNeighbors[j];
        atomWithMostNeighbors = j;
      }
    }
    /*atomWithMostNeighbors = i;*/  /* No sort for debugging */
    /* Now swap the current atom with the "best" atom found */
    /* We will be swapping atoms i and j */
    if (!atomWithMostNeighbors) bug(11);
    j = atomWithMostNeighbors;
    /* Renumber all neighbors (any better way to do this?) */
    for (k = 1; k <= goodAtoms; k++) {
      for (l = 1; l <= atomNeighbors[k]; l++) {
        if (atomNeighbor[k][l] == i) {
          atomNeighbor[k][l] = j;
        } else if (atomNeighbor[k][l] == j) {
          atomNeighbor[k][l] = i;
        }
      }
    }
    /* Swap the neighbor lists of atoms i and j */
    l = atomNeighbors[i];
    atomNeighbors[i] = atomNeighbors[j];
    atomNeighbors[j] = l;
    for (k = 1; k <= goodAtoms; k++) {
      if (k > atomNeighbors[i] && k > atomNeighbors[j]) break;
      /* If one list is longer than the other we are moving
         uninitialized array elements but that should be OK */
      l = atomNeighbor[i][k];
      atomNeighbor[i][k] = atomNeighbor[j][k];
      atomNeighbor[j][k] = l;
    }
    /* Swap other things */
    l = atomMap[i];
    atomMap[i] = atomMap[j];
    atomMap[j] = l;
    atomReverseMap[atomMap[i]] = i;
    atomReverseMap[atomMap[j]] = j;
  } /* next i */


  for (i = 1; i <= vectors; i++) {
    vecUsed[i] = 0; /* 0 means available for use */
  }
  for (i = 1; i <= goodAtoms; i++) {
    atomVec[i] = 0; /* 0 means not yet assigned */
  }

  n = 1;

  if (verboseMode) printf(
"#%ld There are %ld atoms (in multiple blocks) and %ld possible vectors.\n",
      lattices, goodAtoms, vectors);

  if (goodAtoms > vectors) {
    if (verboseMode) printf("#%ld There are more atoms than vectors.\n",
        lattices);
    successFlag = 0;
    goto print_point;
  }


  /* Populate the "lower neighbors" arrays (used for slight speedup of
     backtrack algorithm) */
  for (i = 1; i <= goodAtoms; i++) {
    atomLowerNeighbors[i] = 0;
    for (j = 1; j <= atomNeighbors[i]; j++) {
      if (atomNeighbor[i][j] > i) continue;
      if (atomNeighbor[i][j] == i) bug(12);

      atomLowerNeighbors[i]++; /* Number of smaller neighbors */
      atomLowerNeighbor[i][atomLowerNeighbors[i]]
          = atomNeighbor[i][j];
    }
  }

  successFlag = 1; /* Initialize flag that vector assignment was found */
  while (1) {

    if (n > goodAtoms) { /* Success */
      break;
    }

    /* Assign the next available vector to this atom */
    foundFlag = 0;
    /* Deassign the current vector from this atom, if any */
    k = atomVec[n];
    if (k > 0) {
      vecUsed[k] = 0;
      atomVec[n] = 0;
    }
    /* Get the next vector that can be assigned to atom */
    for (i = k + 1; i <= vectors; i++) {
      if (vecUsed[i]) continue;
      /* If it is not a "labeled" atom, we can only select from
         the unlabeled vectors */
      if (i > unlabeledVectors) {
        if (dims != 3 || noKick == 0) bug(14);
        /* The criterion for "labeled" is = 1 block, so if > 1 blocks
           then exit the loop since we can't use
           unlabeledVectors + 1 <= i <= vectors */
        if (atomBlocks[atomMap[n]] > 1) break;
      }
      /* Check to make sure this vector is compatible with the atom's
         (lower-numbered) neighbors */
      conflict = 0;
      for (j = 1; j <= atomLowerNeighbors[n]; j++) {
        /* Check to see if the scalar product of the neighboring vector
           is zero (this is the key criterion) */
        if (vecProd[i][atomVec[atomLowerNeighbor[n][j]]] != 0) {
          /* Collision */
          conflict = 1;
          break;
        }
      }
      if (!conflict) {
        /* Found a good assignment */
        vecUsed[i] = 1;
        atomVec[n] = i;
        foundFlag = 1;
        break;
      }
    }

    if (foundFlag) {
      n++; /* Go to next atom */
      continue;
    }

    /* We have exhausted possibilities, so we must backtrack */

    if (atomVec[n]) bug(13); /* Should have been deassigned above */
    n--;
    backtrackCountx++;
    if (backtrackLimit != 0 && backtrackCountx >= backtrackLimit) {
      successFlag = 0; /* Timeout */
      break;
    }
    if (n == 0) {
      successFlag = 0; /* No good assignment is possible */
      break;
    }
  } /* while 1 */

  /* backtrackCount is for informational purposes */
  /*if (!oneLineDisplay) printf("Backtrack count = %ld\n", backtrackCountx);*/
  *backtrackCount = backtrackCountx;  /* return argument */


 print_point:
  if (backtrackLimit != 0 && backtrackCountx >= backtrackLimit) {
    printf("#%ldtimeout%ld:: ", lattices, backtrackLimit);
  } else {
    printf("#%ld %s:: ", lattices, successFlag ? "pass" : "fail");
  }
  /* Print stripped MMP diagram */
  for (i = 1; i <= blocks; i++) {
    for (j = 1; j <= blockSize[i]; j++) {
      if (atomBlocks[block[i][j]] == 1 && noKick == 0) continue;
      printf("%c", ATOM_MAP[block[i][j] - 1]);
      /* Print "*" to "label" atom that wasn't kicked out */
      if (atomBlocks[block[i][j]] == 1 && noKick == 1)
        printf("*");
    }
    printf("%c", i < blocks ? ',' : '.');
  }
  if (successFlag) {
    /* Print vectors */
    printf("{");

    if (orthogonalBlockDisplay) {

      /* This is the old-style display that prints the vectors in blocks
         matching the block atoms in the MMP diagram.  Use the -ob qualifier
         to invoke this display mode. */
      for (i = 1; i <= blocks; i++) {
        printf("{");
        for (j = 1; j <= blockSize[i]; j++) {
          if (atomBlocks[block[i][j]] == 1 && noKick == 0) continue;
          printf("{");
          for (k = 1; k <= dims; k++) {
            l = vecCoeff[atomVec[atomReverseMap[block[i][j]]]][k];
            if (!sqrt2Mode) {
              printf("%ld", l);
            } else { /* Square root of 2 mode - +-sqrt2 is mapped to +-1000 */
              if (l == 1000) {
                printf("Sqrt[2]");
              } else if (l == -1000) {
                printf("-Sqrt[2]");
              } else {
                printf("%ld", l);
              }
            }
            printf("%c", k < dims ? ',' : '}');
          }
        }
        printf("}");
      }

    } else {

      /* This is the new style per mp/nm email of 27-Feb-04, where each
         vector is displayed only once in atom order 123...ABC...abc... */
      for (j = 1; j <= atoms; j++) {
        if (atomBlocks[j] == 1 && noKick == 0) continue;
        printf("{");
        for (k = 1; k <= dims; k++) {
          l = vecCoeff[atomVec[atomReverseMap[j]]][k];
          if (!sqrt2Mode) {
            printf("%ld", l);
          } else { /* Square root of 2 mode - +-sqrt2 is mapped to +-1000 */
            if (l == 1000) {
              printf("Sqrt[2]");
            } else if (l == -1000) {
              printf("-Sqrt[2]");
            } else {
              printf("%ld", l);
            }
          }
          printf("%c", k < dims ? ',' : '}');
        }
      }

    }

    printf("}");
  }
  printf("\n");
  return successFlag;
} /* findVectorAssignment */



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


/* Bug check */
void bug(int bugNum)
{
  print2("?Error: Program bug # %d\n", bugNum);
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
