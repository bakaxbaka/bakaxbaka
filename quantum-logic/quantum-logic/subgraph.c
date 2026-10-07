/* subgraph.c */     /* Checks whether a hypergraph is a subgraph of another */
#define VERSION "0.7 27-Apr-2010"
/* 0.7 27-Apr-2010 nm Added -ss (subset) option */

/* To run this program, type:
      subgraph < file1 > file2
   where
      file1 = input file with MMP diagrams in Brendan McKay's format
      file2 = output file saying whether input is a subgraph of Peres' MMP
   See  subgraph --help  for more options and explanation.
*/

/*****************************************************************************/
/*       Copyright (C) 2008  NORMAN D. MEGILL  <nm at alum.mit.edu>          */
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

/* Emulation of BASIC string assignment */
/* 'let' MUST be used to assign vstrings, e.g. 'let(&abc, "Hello"); */
/* Empty string deallocates memory, e.g. 'let(&abc, ""); */
void let(vstring *target, vstring source);

/* Emulation of BASIC string concatenation - last argument MUST be NULL */
/* e.g. 'cat(string1, ..., stringN, NULL);' */
vstring cat(vstring string1,...);

/* Emulation of BASIC linput (line input) statement; returns NULL if EOF */
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

/* Emulation of Progress 4GL string functions, added 11/25/98 */
vstring entry(long element, vstring list);
long lookup(vstring expression, vstring list);
long numEntries(vstring list);
long entryPosition(long element, vstring list);

/* Output logging */
/* Print to log file as well as terminal if fplog opened */
void print2(char* fmt,...);
FILE *fplog = NULL;

/* "Safe" I/O that emulates VMS file versioning with 'generations=10' */
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
/************************** that you shouldn't touch *************************/
/*****************************************************************************/

/* Constants */

/* The reference MMP (hard-coded for now; later this could be an input
   parameter for a more general subhypergraph program) */
#define REF_MMP "1234,4567,789A,ABCD,DEFG,GHI1,12IJ,345K,678L,7LOG,68FH," \
   "1J9B,AMI2,4KCE,DN35,CDEN,IJK5,38KL,6BML,9EMN,CHNO,2JOF,9ABM,OFGH."


/* Mapping for MMP diagram atoms */
#define ATOM_MAP "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs" \
    "tuvwxyz!\"#$%&'()*-/:;<=>?@[\\]^_`{|}~"
/* Length of above string */
#define MAX_ATOMS 90
/* Maximum number of blocks */
#define MAX_BLOCKS 128
/* Minimum block size */
#define MIN_BLOCK_SIZE 2
/* Maximum block size */
#define MAX_BLOCK_SIZE 10

/* Global variables */
char oneLineDisplay = 0;
char verboseMode = 0;
char doubleInputMode = 0; /* 1 = input lines are of form input + " " + ref */
char subsetMode = 0;  /* Renormalize test diagram to be subset of ref */
char exchangeInpAndRef = 0; /* 1 = exchange input and ref before test */
char refFromFile = 0; /* 1 = -rf qualifier, with possibly multiple refs */
char noErrorCheck = 0;
long diagrams = 0;
/* The following were taken out of testForSubgraph() since they need to
   be referenced externally */
/* To store input MMP */
long blocks;
long atoms;
long blockSize[MAX_BLOCKS + 1];
long block[MAX_BLOCKS + 1][MAX_BLOCK_SIZE + 1];
/* To store ref MMP */
/* (The 'static' is redundant, but needed if this array is ever put back into
   testForSubgraph()) */
/*static*/ long refBlock[MAX_BLOCKS + 1][MAX_BLOCK_SIZE + 1];
long inpToRefBlockMap[MAX_BLOCKS + 1];

long backtrackCount = 0; /* For user information */
long totalBacktrackCount = 0; /* For user information */



/* Prototypes */
char testForSubgraph(vstring inputMMP, vstring refMMP);
vstring parseMMP(vstring MMPDiagram);




/******************** Main program *******************************************/

int main(int argc, char *argv[])
{

  /* Integer variable declarations */

  /* This is how you declare some strings you want to work with */
  /* They MUST be initialized to the empty string, never to anything else */
  vstring str1 = "";
  vstring str2 = "";
  long arg;
  char success;
  FILE *fref = NULL;
  vstring inpMMP = "";
  vstring refMMP = "";
  vstring printInpMMP = "";
  vstring printRefMMP = "";
  long p, i, j;
  long refDiagrams = 0;
  long refDiagram = 0;

  if (strlen(ATOM_MAP) != MAX_ATOMS) bug(1);

  for (arg = 1; arg < argc; arg++) {
    if (!strcmp(argv[arg], "-1")) {
      oneLineDisplay = 1;
    } else if (!strcmp(argv[arg], "-ne")) {
      noErrorCheck = 1;
    /*
    } else if (!strcmp(argv[arg], "-v")) {
      verboseMode = 1;
    */


    /* Process options to read the reference diagram */
    } else if (!strcmp(argv[arg], "-r")) {
      arg++;
      /* Take reference diagram from field after "-r" */
      let(&refMMP, argv[arg]);
    } else if (!strcmp(argv[arg], "-rf")) {
      if (refMMP[0]) {
        fprintf(stderr,
   "?Only one of \"-r\" or \"-rf\" or \"-r1\" or \"-ir\" may be specified.\n");
        exit(1);
      }
      refFromFile = 1; /* Set flag there are possibly multiple refs */
      arg++;
      /* Take file with reference diagram from field after "-r" */
      fref = fopen(argv[arg], "r");
      if (fref == NULL) {
        fprintf(stderr,
            "?File \"%s\" could not be found or opened.\n", argv[arg]);
        exit(1);
      }
      /* Count the reference diagrams in the -rf file */
      refDiagrams = 0;
      while (linput(fref, NULL, &refMMP) != NULL) {
        refDiagrams++;
      }
      if (refDiagrams == 0) {
        fprintf(stderr,
            "?File \"%s\" is empty.\n", argv[arg]);
        exit(1); /* NULL means EOF */
      }
      /*rewind(fref);*/ /* Reset to beginning of file */ /* Done before scan*/
      let(&refMMP, ""); /* The -rf fref scan will assign it */
    } else if (!strcmp(argv[arg], "-r1")) {
      if (refMMP[0]) {
        fprintf(stderr,
   "?Only one of \"-r\" or \"-rf\" or \"-r1\" or \"-ir\" may be specified.\n");
        exit(1);
      }
      /* Take reference diagram from first line in stdin (standard input) */
      if (linput(NULL, NULL, &refMMP) == NULL) {
        fprintf(stderr,
            "?There are no input lines.\n");
        exit(1);
      }
      /* Clean off carriage return (for Windows/Cygwin) and spaces */
      let(&refMMP, edit(refMMP, 2 + 4));
    } else if (!strcmp(argv[arg], "-ir")) {
      if (refMMP[0]) {
        fprintf(stderr,
   "?Only one of \"-r\" or \"-rf\" or \"-r1\" or \"-ir\" may be specified.\n");
        exit(1);
      }
      /* Take reference diagram from 2nd field of each stdin input line */
      doubleInputMode = 1;
    /* (End of processing options to read the reference diagram */


    } else if (!strcmp(argv[arg], "-x")) {
      /* Swap input and reference before subgraph test */
      exchangeInpAndRef = 1;
    } else if (!strcmp(argv[arg], "-ss")) {
      /* Subset mode */
      subsetMode = 1;
    /* (End of processing options to read the reference diagram */


    } else if (!strcmp(argv[arg], "--help")) {
printf("subgraph.c  Version %s\n", VERSION);
printf("To run this program, type:\n");
/*
printf("   subgraph [-1] [-ne] [-v] < file1 > file2\n");
*/
printf(
"   subgraph [-1] [-ne] [-r ref | -rf reffile | -r1 | -ir] [-x]\n");
printf(
"       [-1] [-v] [-ss] < file1 > file2\n");
printf(
"where the optional qualifiers may be given in any order:\n");
printf(
"   -1 = display 1-line output for use with Unix pipe filters:  the output\n");
printf(
"     consists of pass/fail info followed by \":: \", then the input\n");
printf(
"     (potential) subgraph MMP, then \" \", then the reference hypergraph MMP.\n");
printf(
"     \"fails\" means \"the input MMP is not a subgraph of the reference MMP.\"\n");
printf(
"     When there are multiple references (-rf), each input line will\n");
printf(
"     turn into several output lines, one for each reference.\n");
printf(
"   -ne = skip some error checking for speedup\n");
/*
printf(
"   -v = verbose mode for debugging\n");
*/
printf(
"   -r = use the next argument as the reference diagram\n");
printf(
"   -rf = use the next argument as the file with the reference diagram(s)\n");
printf(
"   -r1 = use the first line from \"file1\" as the reference diagram\n");
printf(
"   -ir = \"file1\" format is input diagram + space + reference diagram\n");
printf(
"     (If none of -r, -rf, -r1, -ir then internal REF_MMP is used.)\n");
printf(
"   -x = exchange input and reference before the subgraph test.  E.g.\n");
printf(
"     \"subgraph -r 1234,4567. -x < file1\" will treat \"file1\" as a list\n");
printf(
"     of reference diagrams and test whether \"1234,4567.\" is a subgraph.\n");
printf(
"     Since -x may be confusing, the default output shows the detailed\n");
printf(
"     assumptions being made.\n");
printf(
"   -ss = reformat each input diagram to match a subset of the blocks\n");
printf(
"     in the reference diagram.  Note: -ss affects only the -1 mode.\n");
printf(
"     Only passing (subgraph) lines are reformatted.\n");
printf(
"   file1 = input file with hypergraphs in MMP diagram format\n");
printf(
"   file2 = output file with subgraph test results\n");
printf("For this help message, type:  subgraph --help\n");
printf("\n");
printf(
"Purpose:  This program determines whether an input hypergraph in MMP\n");
printf(
"diagram format is a subgraph of the specified reference hypergraph.\n");
printf(
"The MMP diagram notation is due to Brendan McKay and is the same as for\n");
printf(
"Greechie diagrams as described in the --help for the program latticeg.c\n");
printf("\n");
printf("Example of use:\n");
printf("  subgraph < test.mmp\n");
printf("where test.mmp contains the two lines:\n");
printf("  1234,4567.\n");
printf("  1234,1235.\n");
printf("corresponding to two diagrams, the first a subgraph of REF_MMP and\n");
printf("the second one not a subgraph.\n");
printf("\n");
printf(
"Acknowledgment:  Thanks to Brendan McKay for suggesting the main\n");
printf(
"isomorphic subgraph algorithm for hypergraphs.\n");
      goto return_point;
    } else {
      fprintf(stderr,
          "?Unrecognized option - type \"subgraph --help\" for usage\n");
      exit(1);
    }
  }


  if (!doubleInputMode && !refFromFile) {
    if (!refMMP[0]) {
      /* None of -r, -rf, or -r1 was specified; use internal hard-coded ref */
      let(&refMMP, REF_MMP);
      if (!oneLineDisplay && !exchangeInpAndRef) {
        printf(
         "The reference diagram (hard-coded in the program as REF_MMP) is:\n");
        printf("  %s\n", refMMP);
      }
    } else {
      if (!oneLineDisplay && !exchangeInpAndRef) {
        printf("The reference diagram is:\n");
        printf("  %s\n", refMMP);
      }
    }
  }


  while (1) { /* Scan the < file1 (standard input) lines */
    /* Get line from standard input */
    if (linput(NULL, NULL, &str1) == NULL) break; /* NULL means EOF */
    /* Clean off carriage return (for Windows files under Cygwin) and spaces */
    /* 4=remove cr/lf, 8=trim leading spaces, 16=reduce spaces, 128=trailing */
    let(&str1, edit(str1, 4 + 8 + 16 + 128));

    /* Special feature for debugging; maybe I'll make it permanent:
       if the first character of the line is '#', treat it as comment.
       However, right now the first line for -r1 is not handled, nor
       is any line of the -rf file. */
    if (str1[0] == '#') continue;

    diagrams++;

    if (refFromFile) {
      refDiagram = 0;
      rewind(fref); /* Reset to beginning of -rf file */
    }
    while (1) { /* Scan the -rf file (or just one pass if no -rf) */

      if (refFromFile) {
        /* Get the next reference MMP from the -rf file */
        if (linput(fref, NULL, &refMMP) == NULL) break; /* NULL means EOF */
        /* Clean off carriage return (for Windows/Cygwin) and spaces */
        let(&refMMP, edit(refMMP, 2 + 4));
        refDiagram++;
      }

      /* Assume input line is in the form inpMMP+" "+refMMP */
      if (doubleInputMode) {
        p = instr(1, str1, " ");
        if (p == 0) {
          fprintf(stderr, "%s\n", str1);
          fprintf(stderr, !exchangeInpAndRef ?
  "?Format should be input diagram + space + reference diagram in -ir mode\n"
            :
  "?Format should be reference diagram + space + input diagram in -ir mode\n");
          exit(1);
        }
        let(&inpMMP, left(str1, p - 1));
        let(&refMMP, right(str1, p + 1));
        if (!oneLineDisplay) {
          printf("The reference diagram for #%ld is:\n", diagrams);
          printf("  %s\n", !exchangeInpAndRef ? refMMP : inpMMP);
        }
      } else {
        let(&inpMMP, str1);
        if (exchangeInpAndRef || refFromFile) {
          if (!oneLineDisplay) {
            if (!refFromFile || refDiagrams == 1) {
              printf("The reference diagram for #%ld is:\n", diagrams);
            } else {
              printf(
                "Case %ld of %ld:  The reference diagram for #%ld below is:\n",
                  refDiagram, refDiagrams, diagrams);
            }
            printf("  %s\n", !exchangeInpAndRef ? refMMP : inpMMP);
          }
        }
      }

      if (!oneLineDisplay) {
        printf("#%ld %s\n", diagrams, !exchangeInpAndRef ? inpMMP : refMMP);
      }
      backtrackCount = 0;

      /********* Do the test ********/
      success = testForSubgraph(!exchangeInpAndRef ? inpMMP : refMMP,
           !exchangeInpAndRef ? refMMP : inpMMP);
                                        /* 1 = is subgraph, 0 = not subgraph */

      if (!oneLineDisplay) {
        if (!success) {
          printf(
           "  The above input diagram is not a subgraph of the reference.\n");
        }
      }
      if (oneLineDisplay) {

        if(!exchangeInpAndRef) {
          let(&printInpMMP, inpMMP);
          let(&printRefMMP, refMMP);
        } else {
          let(&printInpMMP, refMMP);
          let(&printRefMMP, inpMMP);
        }

        if (subsetMode && success) {
          /* Reformat the input diagram to be a subset of the reference */
          /* Don't do this unless it is a subgraph, otherwise the mapping
             is meaningless */
          p = 0;
          for (i = 1; i <= blocks; i++) {
            for (j = 1; j <= blockSize[i]; j++) {
              printInpMMP[p] = ATOM_MAP[refBlock[inpToRefBlockMap[i]][j]-1];
              p++;
            }
            printInpMMP[p] = (i == blocks) ? '.' : ',';
            p++;
          }
          if (p != strlen(!exchangeInpAndRef ? inpMMP : refMMP)) bug(801);
          if (printInpMMP[p] != 0) bug(802);
        }

        /* nm 8-Nov-2008 Make the 1-line output after "::" _always_ be the
           input MMP then space then the ref MMP */
        /* (was: "let(&str2, str1);") */
        let(&str2, cat(printInpMMP, " ", printRefMMP, NULL));

        if (!refFromFile) {
          /* #16 ((37)) passes:: 8HP,9KP,25A,23L,BCQ,5DN,7CL,9EN,67F,... */
          printf("#%ld ((%ld)) %s:: %s\n", diagrams, backtrackCount,
              success ? "passes" : "fails", str2);
        } else {
          /* #16 r#2 ((37)) passes:: 8HP,9KP,25A,23L,BCQ,5DN,7CL,9EN,67F,... */
          printf("#%ld %c#%ld ((%ld)) %s:: %s\n", diagrams,
              !exchangeInpAndRef ? 'r' : 'i',
              refDiagram,
              backtrackCount, success ? "passes" : "fails", str2);
        }
      } else {
        printf("  Backtrack count = %ld\n", backtrackCount);
      }
      totalBacktrackCount += backtrackCount;
      if (!refFromFile) break; /* not the -rf option, there is only 1 pass */
    } /* end while (1) for -rf file scan */
  } /* end while (1) for the stdin scan */

  if (!oneLineDisplay) {
    printf("Total diagrams = %ld  Total backtrack count = %ld",
        diagrams, totalBacktrackCount);
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


/* Caller must deallocate returned string. */
char testForSubgraph(vstring inputMMP, vstring refMMP)
{
  static char refParsed = 0; /* To save time if already parsed */
  static char refBlockUsesAtom[MAX_BLOCKS + 1][MAX_ATOMS + 1];

  /* To store reference REF_MMP */
  static long refBlocks;
  static long refAtoms;
  static long refBlockSize[MAX_BLOCKS + 1];

  char blockUsesAtom[MAX_BLOCKS + 1][MAX_ATOMS + 1];
  long i, j, k, wblock, refAtom, inpAtom;
  char found = 0;
  char result; /* Returned value of testForSubgraph: 1 = has subgraph */
  vstring str1 = "";
  char refBlockUsed[MAX_BLOCKS + 1];
  char blockAtomTested[MAX_BLOCK_SIZE + 1];

  /* For user information */
  long inpAtomToRefAtom[MAX_BLOCKS + 1][MAX_ATOMS + 1];
  long refAtomToInpAtom[MAX_BLOCKS + 1][MAX_ATOMS + 1];

#define ONLY_ONE_REF_MMP 1
  /* Parse the reference hypergraph in MMP format */
  if (!ONLY_ONE_REF_MMP || !refParsed || doubleInputMode
      || exchangeInpAndRef || refFromFile) { /* Save time if already parsed */
    refParsed = 1;
    str1 = parseMMP(refMMP);
    let(&str1, "");
    /* Transfer information to the reference storage */
    refAtoms = atoms;
    refBlocks = blocks;
    for (i = 1; i <= refBlocks; i++) {
      refBlockSize[i] = blockSize[i];
      for (j = 1; j <= refBlockSize[i]; j++) {
        refBlock[i][j] = block[i][j];
      }
    }
    /* Build the "block uses atom" table */
    for (i = 1; i <= refBlocks; i++) {
      for (j = 1; j <= refAtoms; j++) {
        refBlockUsesAtom[i][j] = 0;  /* Initialize */
      }
      for (j = 1; j <= refBlockSize[i]; j++) {
        refBlockUsesAtom[i][refBlock[i][j]] = 1; /* Set the flag */
      }
    }
  }

  /* Parse the input hypergraph in MMP format */
  str1 = parseMMP(inputMMP);
  let(&str1, "");
  /* Build the "block uses atom" table */
  for (i = 1; i <= blocks; i++) {
    for (j = 1; j <= atoms; j++) {
      blockUsesAtom[i][j] = 0;  /* Initialize */
    }
    for (j = 1; j <= blockSize[i]; j++) {
      blockUsesAtom[i][block[i][j]] = 1; /* Set the flag */
    }
  }

  if (blocks > refBlocks) {
    result = 0; /* input > ref not a subgraph */
    return result;
  }

  for (i = 1; i <= refBlocks; i++) {
    refBlockUsed[i] = 0; /* Initialize */
  }

  wblock = 1; /* Working block of input hypergraph */
  inpToRefBlockMap[wblock] = 0; /* Initialize input to ref block map */

  /* Initialize the user information mapping */
  /*
  for (i = 1; i <= atoms; i++) {
    inpAtomToRefAtom[wblock][i] = 0;
  }
  for (i = 1; i <= refAtoms; i++) {
    refAtomToInpAtom[wblock][i] = 0;
  }
  */

  /* Get next candidate from reference hypergraph */
  while (1) {
    inpToRefBlockMap[wblock]++;
    if (inpToRefBlockMap[wblock] > refBlocks) {
      /* Backtrack */
      backtrackCount++;
      wblock--;
      if (wblock == 0) {
        /* We've exhausted the backtracking; give up */
        result = 0;
        return result;
      }
      refBlockUsed[inpToRefBlockMap[wblock]] = 0;
      continue;
    }

    /* Find the next usable unassigned block from the reference */
    if (refBlockUsed[inpToRefBlockMap[wblock]]) { /* It's used by an earlier
                                                     input block */
      continue;
    }
    if (refBlockSize[inpToRefBlockMap[wblock]] != blockSize[wblock]) {
                 /* Size mismatch */
      continue;
    }

    /* See if we still have an isomorphism when the new block is added */
    for (i = 1; i <= blockSize[wblock]; i++) {
      /* We will set this flag for each successful atom connectivity test */
      blockAtomTested[i] = 0;
    }

    if (!oneLineDisplay) {
      /* Initialize the atom mapping information for this trial block */
      if (wblock == 1) {
        /* Initialize the user information mapping */
        for (i = 1; i <= atoms; i++) {
          inpAtomToRefAtom[wblock][i] = 0;
        }
        for (i = 1; i <= refAtoms; i++) {
          refAtomToInpAtom[wblock][i] = 0;
        }
      } else {
        /* Copy the user information atom mapping from the previous block */
        for (i = 1; i <= atoms; i++) {
          inpAtomToRefAtom[wblock][i] = inpAtomToRefAtom[wblock - 1][i];
        }
        for (i = 1; i <= refAtoms; i++) {
          refAtomToInpAtom[wblock][i] = refAtomToInpAtom[wblock - 1][i];
        }
      }
    }

    /* Scan each atom in the added ref block and see if there is an atom
       in the input block with the same connectivity */
    for (i = 1; i <= blockSize[wblock]; i++) {
      refAtom = refBlock[inpToRefBlockMap[wblock]][i];
      /* Scan the atoms in the corresponding input block */
      for (j = 1; j <= blockSize[wblock]; j++) {
        if (blockAtomTested[j]) continue;
        found = 1;
        /* Compare the connectivity with all previous blocks */
        inpAtom = block[wblock][j];
        for (k = 1; k < wblock; k++) {
          if (refBlockUsesAtom[inpToRefBlockMap[k]][refAtom]
              != blockUsesAtom[k][inpAtom]) {
            /* Connectivity match failed */
            found = 0;
            break;
          }
        }
        if (found) {
          /* This is a good connectivity match; use it */
          blockAtomTested[j] = 1;

          if (!oneLineDisplay) {
            /* Assign atom mapping for user info */
            if (inpAtomToRefAtom[wblock][inpAtom] == 0) {
              /* It hasn't been assigned yet */
              if (refAtomToInpAtom[wblock][refAtom] != 0) {

/*D*/ /* For debugging bug #2; can be removed */
/*D*/printf("rA %c iA %c r2i %c i2r %c wb %ld i2rbl %ld\n",
/*D*/ ATOM_MAP[refAtom-1],
/*D*/ ATOM_MAP[inpAtom-1],
/*D*/ ATOM_MAP[refAtomToInpAtom[wblock][refAtom]-1],
/*D*/ ATOM_MAP[inpAtomToRefAtom[wblock][inpAtom]-1],
/*D*/ wblock,
/*D*/ inpToRefBlockMap[wblock]);

                bug(2);
              }
              inpAtomToRefAtom[wblock][inpAtom] = refAtom;
              refAtomToInpAtom[wblock][refAtom] = inpAtom;
            } else {
              /* If it changed, swap the mapping to keep it 1-to-1 */
              if (inpAtomToRefAtom[wblock][inpAtom] != refAtom) {
                if (refAtomToInpAtom[wblock][refAtom] == inpAtom) {
                  bug(3);
                }
                inpAtomToRefAtom[wblock][refAtomToInpAtom[wblock][refAtom]]
                    = inpAtomToRefAtom[wblock][inpAtom];
                refAtomToInpAtom[wblock][inpAtomToRefAtom[wblock][inpAtom]]
                    = refAtomToInpAtom[wblock][refAtom];
                inpAtomToRefAtom[wblock][inpAtom] = refAtom;
                refAtomToInpAtom[wblock][refAtom] = inpAtom;
              } else {
                if (refAtomToInpAtom[wblock][refAtom] != inpAtom) {
                  bug(4);
                }
              }
            } /* end if (inpAtomToRefAtom[wblock][inpAtom] == 0) else */
          } /* end if (!oneLineDisplay) */

          break;
        } /* end if (found) */
      } /* next j (atom in input hypergraph block) */
      if (!found) break;
    } /* next i (atom in ref hypergraph trial block) */
    if (!found) {
      /* There is an atom in the trial refBlock that has different
         connectivity from all atoms in the input block */
      continue;
    }

    /* We found a good ref hypergraph block to add.  Go on to next one. */
    /* Add the next block from the input hypergraph */
    refBlockUsed[inpToRefBlockMap[wblock]] = 1;
    wblock++;
    /* If we're past the last input hypergraph block we're done; success. */
    if (wblock > blocks) {
      result = 1;
      if (!oneLineDisplay) {
        printf(
"  Isomorphism:  ref block numbers, ref blocks, map to input block atoms:\n");

        /* Print the reference block numbers */
        let(&str1, "    ");
        for (i = 1; i <= blocks; i++) {
          let(&str1, cat(str1,
             space(i == 1 ? 0 : blockSize[inpToRefBlockMap[i - 1]] + 1 -
                 strlen(str(inpToRefBlockMap[i - 1]))),
             str(inpToRefBlockMap[i]), NULL));
        }
        printf("%s\n", str1);
        let(&str1, ""); /* Deallocate */

        /* Print the reference blocks */
        printf("    ");
        for (i = 1; i <= blocks; i++) {
          for (j = 1; j <= blockSize[i]; j++) {
            printf("%c", ATOM_MAP[refBlock[inpToRefBlockMap[i]][j]-1]);
          }
          printf("%c", i == blocks ? '.' : ',');
        }
        printf("\n");

        /* Print the corresponding atoms in the input blocks */
        printf("    ");
        for (i = 1; i <= blocks; i++) {
          for (j = 1; j <= blockSize[i]; j++) {
            k = refBlock[inpToRefBlockMap[i]][j];
            printf("%c", ATOM_MAP[refAtomToInpAtom[blocks][k]-1]);
          }
          printf("%c", i == blocks ? '.' : ',');
        }
        printf("\n");

      }
      return result;
    }

    /* Copy the user information atom mapping from the previous block */
    /*
    for (i = 1; i <= atoms; i++) {
      inpAtomToRefAtom[wblock][i] = inpAtomToRefAtom[wblock - 1][i];
    }
    for (i = 1; i <= refAtoms; i++) {
      refAtomToInpAtom[wblock][i] = refAtomToInpAtom[wblock - 1][i];
    }
    */

    inpToRefBlockMap[wblock] = 0; /* Initialize input to ref block map */
  } /* end while (1) */
} /* end of testForSubgraph() */

/* This function parses the input MMP diagram and assigns the following
   global variables and arrays:
     blocks = # blocks (edges)
     atoms = largest atom (vertex) #, starting at 1 (NOT necessarily the
             # of atoms though, if the input diagram skips atoms)
     blockSize[<block>]  <block> = 1,...,blocks
     block[<block>][<j>] = atom number, where <block> = 1,...,blocks,
                           <j> = 1,...,blockSize[]
*/
/* Caller must deallocate returned string. */
/* (Currently, this function always returns an empty string, so nothing has
   to be done.) */
vstring parseMMP(vstring MMPDiagram) {
  long i, j, k, n;
  vstring str1 = "";

  n = strlen(MMPDiagram);

  if (!noErrorCheck) {
    /* The calling routine should ensure this */
    if (strchr(MMPDiagram, ' ') != NULL) {
      fprintf(stderr, "#%ld: %s\n", diagrams, MMPDiagram);
      fprintf(stderr,
          "?Error: the diagram may not contain a space.\n");
      exit(1);
    }

    /* MMPDiagram has period - assume new (Brendan) compact standard */
    if (MMPDiagram[0] == '+') {
      fprintf(stderr, "#%ld: %s\n", diagrams, MMPDiagram);
      fprintf(stderr,
          "?Error: '+' notation for large diagrams is not implemented.\n");
      exit(1);
    }
    if (MMPDiagram[n - 1] != '.') {
      fprintf(stderr, "#%ld: %s\n", diagrams, MMPDiagram);
      fprintf(stderr, "?Error: Last character should be a period.\n");
      exit(1);
    }

    /* if (instr(1, left(MMPDiagram, n - 1), ".") != 0) { */
    if (strchr(MMPDiagram, '.') != MMPDiagram + n - 1) {
      fprintf(stderr, "#%ld: %s\n", diagrams, MMPDiagram);
      fprintf(stderr, "?Error: Period can only be last character.\n");
      exit(1);
    }
    if (n == 1) {
      fprintf(stderr, "#%ld: %s\n", diagrams, MMPDiagram);
      fprintf(stderr, "?Error: Diagram must have at least one block.\n");
      exit(1);
    }
  }

  atoms = 0;
  blocks = 1;
  blockSize[blocks] = 0;
  for (i = 0; i < n; i++) {
    if (MMPDiagram[i] == ',' || MMPDiagram[i] == '.') {
      /* End of block */
      if (blockSize[blocks] < MIN_BLOCK_SIZE) {
        fprintf(stderr, "#%ld: %s\n", diagrams, MMPDiagram);
        fprintf(stderr, "?Error: Minimum block size is %ld.\n",
            (long)MIN_BLOCK_SIZE);
        exit(1);
      }
      if (MMPDiagram[i] == ',') {
        /* Start of new block */
        blocks++;
        if (blocks > MAX_BLOCKS) {
          fprintf(stderr, "#%ld: %s\n", diagrams, MMPDiagram);
          fprintf(stderr, "?Error: Maximum blocks allowed is %ld.\n",
              (long)MAX_BLOCKS);
          exit(1);
        }
        blockSize[blocks] = 0;
      }
      continue;
    }
    /* Get the atom number */
    /*j = instr(1, ATOM_MAP, chr(MMPDiagram[i]));*/
    /*let(&str1, "");*/ /* Deallocate chr call */

    if (!noErrorCheck) {
      if (strchr(ATOM_MAP, MMPDiagram[i]) == NULL) {
        fprintf(stderr, "#%ld: %s\n", diagrams, MMPDiagram);
        fprintf(stderr, "?Error: Illegal character '%c' in diagram.\n",
            MMPDiagram[i]);
        exit(1);
      }
    }
    /* Note: testing for j == 0 instead of above is a bug that should be fixed
       in loopmin.c mmpblimp.c mmpcabello.c states01.c vectorfind.c !!! */
    j = strchr(ATOM_MAP, MMPDiagram[i]) - ATOM_MAP + 1;
    blockSize[blocks]++;
    if (blockSize[blocks] > MAX_BLOCK_SIZE) {
      fprintf(stderr, "#%ld: %s\n", diagrams, MMPDiagram);
      fprintf(stderr, "?Error: Maximum block size is %ld.\n",
          (long)MAX_BLOCK_SIZE);
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
            fprintf(stderr, "#%ld: %s\n", diagrams, MMPDiagram);
            fprintf(stderr,
                "?Error: Duplicate atom numbers in a block.\n");
            exit(1);
          }
        }
      }
    }
  }
  return str1;
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
