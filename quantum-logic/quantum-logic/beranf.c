/*****************************************************************************/
/* beranf.c - Orthomodular Lattice F2 finder (faster than beran.c)           */
/*                                                                           */
/*       Copyright (C) 1998  NORMAN D. MEGILL  <nm@alum.mit.edu>             */
/*             License terms:  GNU General Public License                    */
/*****************************************************************************/
/*34567890123456 (79-character line to adjust text window width) 678901234567*/

#define VERSION "0.2 10-May-00"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>

/* Largest lattice size plus 1 */
#define MAX_NODES 20
/* Maximum number of lattices */
#define MAX_LATTICES 4
/* Binary infix operator list - i is only for Polish conversion */
#define BIN_OPERS "^v#=<OI2345i"
/* Negation prefix operator */
#define NEG_OPER '-'
#define UNIV_IMPL 'i'
/* MAX_STACK is length of longest formula expressed in Polish notation */
#define MAX_STACK 10000
/* List of legal variable names - note v,i,o skipped because of operators */
#define VAR_LIST "abcdefghjklmnpqrstuwxyz"

/******************** Start of string handling prototypes ********************/
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

/* Bug check error */
void bug(int bugNum);

/******************** End of string handling prototypes **********************/

/******************** Prototypes *********************************************/
void printhelp(void);
long omlFind(vstring wffPol);
long omlf2(vstring);
void init(void);
void initLattice(long latticeNum);
char test(vstring polEqn);
vstring toPolish(vstring equation);
char eval(vstring trialEqn);
vstring subFormula(vstring eqn);
char lookupCompl(char arg);
char lookupBinOp(char operation, char arg1, char arg2);

/******************** Global variables ***************************************/
vstring nodeList[MAX_LATTICES][MAX_NODES];
vstring sup[MAX_LATTICES][MAX_NODES][MAX_NODES];
                            /* Supremum (disjunction) table */
vstring nodeNames[MAX_LATTICES];
                           /* List of node names in nodeList order */
long nodes[MAX_LATTICES];
char nodeNameMap[MAX_LATTICES][256];
                          /* Map from node name to lattice entry for speedup */
vstring latticeName[MAX_LATTICES]; /* Name of lattice being worked with */
long currentLattice; /* Lattice currently in use */


char negMap[256]; /* Map of negatives for speedup */
char opMap[256]; /* Map of operators for speedup */

vstring equation = ""; /* Expression being tested */

vstring f2[97]; /* OML F2 canonical expressions */
vstring f2c[97]; /* F2 expression in more compact notation */
vstring f2Pol[97]; /* OML F2 - Polish version for speedup */
long boolMO2[16][6]; /* Boolean case to MO2 cases map */

char skipf2[97]; /* (For special applications) */

/******************** Main program *******************************************/

int main(int argc, char *argv[])
{

  vstring str1 = "";
  vstring str2 = "";
  char xmap = 0; /* Variable mapped to x */
  char ymap = 0; /* Variable mapped to y */
  vstring wffPol = "";
  long i, omlNodeNum;

  init(); /* One-time initialization */

  /* argc is the number of arguments; argv points to array containing them */
  if (argc == 1) {
    printhelp();
    return 0;
  }

  /* Build input expression by concatenating together all arguments */
  for (i = 1; i < argc; i++) {
    let(&str2, argv[i]);
    if (str2[0] == '\'' || str2[0] == '\"') {
      /* Strip quotes */
      let(&str2, seg(str2, 2, strlen(str2) - 1));
    }
    let(&str1, cat(str1, str2, NULL));
  }
  let(&str1, edit(str1, 1 + 2 + 4)); /* Strip spaces & garbage chars */
  printf("%s ", str1); /* Uncomment to include input formula in output */

  /* Map variables to x and y */
  for (i = 0; i < strlen(str1); i++) {
    let(&str2, chr(str1[i]));
    if (instr(1, VAR_LIST, str2) != 0) {
      /* It's a variable */
      if (!xmap && !ymap) {
        /* If only x and y are used, map them to themselves */
        if (str1[i] == 'x') xmap = 'x';
        if (str1[i] == 'y') ymap = 'y';
      }
      if (!xmap && str1[i] != ymap) xmap = str1[i];
      if (!ymap && str1[i] != xmap) ymap = str1[i];
      if (xmap == str1[i]) {
        str1[i] = 'x';
      } else {
        if (ymap == str1[i]) {
          str1[i] = 'y';
        } else {
          printf("?Error - only two variables are allowed\n");
          exit(0);
        }
      }
    }
  }
  let(&str2, ""); /* Deallocate */

  let(&wffPol, "");
  wffPol = toPolish(str1);

  omlNodeNum = omlFind(wffPol);

  if (omlNodeNum) {
    let(&str2, cat(str(omlNodeNum), " ", f2[omlNodeNum], " ",
        f2c[omlNodeNum], NULL));
  } else {
    let(&str2, "? ?"); /* Mismatched result for universal arrow */
  }
  /* Map variables back to original ones */
  for (i = 0; i < strlen(str2); i++) {
    if (str2[i] == 'x') str2[i] = xmap;
    if (str2[i] == 'y') str2[i] = ymap;
  }
  printf("%s\n", str2); /* Print the output */
  let(&str1, ""); /* Deallocate */
  let(&str2, ""); /* Deallocate */
  let(&wffPol, "");
  return 0;
} /* main */

void printhelp(void)
{
vstring a = "";
printf("Usage: beran <expr>\n");
linput(NULL,"Do you want help (Y/N) <Y>?",&a);
if (toupper(a[0]) == 'N') return;
printf("beranf.c - Orthomodular Lattice F2 finder (faster than beran.c)\n");
printf("\n");
printf(
   "Copyright (C) 2000 Norman D. Megill <nm@alum.mit.edu> Version %s\n",
   VERSION);
printf("License terms:  GNU General Public License\n");
printf("\n");
printf("This program takes as its input an arbitrary 2-variable formula\n");
printf("(one or two variables along with orthocomplement, conjunction,\n");
printf("disjunction, and constants 0 [false] and 1 [true]).  It outputs\n");
printf("the equivalent canonical expression corresponding to one of the 96\n");
printf("elements of the free OML (orthomodular lattice) F2.  The canonical\n");
printf("expression is taken from Table 1 p. 82 of L. Beran's _Orthomodular\n");
printf("Lattices: Algebraic Approach_ (1984).\n");
printf("\n");
printf("The output is of the form \"<expr1> <n> <expr2> <expr3>\" where\n");
printf("<expr1> is the input expression, <n> is F2 element\n");
printf("number 1 through 96 according to Beran, <expr2> is the\n");
printf("corresponding canonical expression, and <expr3> is a short\n");
printf("equivalent expression.\n");
printf("\n");
printf("To compile:  Use any ANSI C compiler such as gcc.  The entire\n");
printf("program is contained in the single file beran.c\n");
printf("\n");
printf("\n");
linput(NULL,"Press Enter to continue, q to quit...",&a);
if (toupper(a[0]) == 'Q') return;
printf("\n");
printf("To run:  Type, at the Unix or DOS prompt, \'beran <expression>\',\n");
printf("for example \'beran \"((x^--y)v0)\"\' meaning \"(x AND NOT NOT y)\n");
printf("OR FALSE\".  The expression must be in the strict form\n");
printf("    <atom> := x | y | 0 | 1\n");
printf("    <opr> := ^ | v\n");
printf("    <uopr> := -\n");
printf("    <expr> := <atom> | <uopr> <expr> | ( <expr> <opr> <expr> )\n");
printf("where x, y are variables; 0, 1 are constants; ^ is conjunction; v\n");
printf("is disjunction; and - is negation (orthocomplement).  In\n");
printf("particular, outer parentheses are mandatory unless the expression\n");
printf("is an atom or negated expression, and association of operators\n");
printf("must be explicit.  Negation is a prefix, not postfix, operator.\n");
printf("    \"xvy\" is illegal; \"(xvy)\" is legal\n");
printf("    \"(x)\" is illegal; \"x\" is legal\n");
printf("    \"(-x)\" or \"x-\" is illegal; \"-x\" is legal\n");
printf("    \"(xvyvx)\" is illegal; \"((xvy)vx)\" or \"(xv(yvx))\" is legal\n");
printf("The program does a thorough check for syntax errors.  The input\n");
printf("expression may be enclosed in single or double quotes when it\n");
printf("may be ambiguous to the operating system shell (watch out for\n");
printf("\"<\" in particular!).  Blanks are allowed in the expression.\n");
printf("\n");
linput(NULL,"Press Enter to continue, q to quit...",&a);
if (toupper(a[0]) == 'Q') return;
printf("Very long expressions:  If multiple arguments are given to the program,\n");
printf("they will be joined into a single expression.  This will workaround\n");
printf("operating system limits on argument length.  Example:\n");
printf("   beran \"((x^--\" \"y)v0)\"\n");
printf("is the same as\n");
printf("   beran \"((x^--y)v0)\"\n");
printf("\n");
printf("For convenience the operator list has been extended in this version:\n");
printf("    <opr> := ^ | v | = | < | O | I | 2 | 3 | 4 | 5 | i\n");
printf("where\n");
printf("    ^ = conjunction\n");
printf("    v = disjunction\n");
printf("    # = biimplication: ((x^y)v(-x^-y)) ('=' is alternate for '#')\n");
printf("    < = less-than-or-equal operation:  ((xvy)#y)\n");
printf("    O = ->0 = classical arrow: (-xvy)\n");
printf("    I = ->1 = Sasaki arrow: (-xv(x^y))\n");
printf("    2 = ->2 = Dishkant arrow: (-yI-x)\n");
printf("    3 = ->3 = Kalmbach arrow: (((-x^y)v(-x^-y))v(x^(-xvy)))\n");
printf("    4 = ->4 = non-tollens arrow: (-y3-x)\n");
printf("    5 = ->5 = relevance arrow: (((x^y)v(-x^y))v(-x^-y))\n");
printf("    i = universal arrow (expression must yield same canonical form\n");
printf("        for all of i=I,2,3,4,5 otherwise output is \"? ?\")\n");
linput(NULL,"Press Enter to continue, q to quit...",&a);
if (toupper(a[0]) == 'Q') return;
printf("\n");
printf("Variable names from the list '%s' are allowed\n",
    VAR_LIST);
printf("provided there are no more than two different variables in the\n");
printf("input expression.  However, the Beran canonical expression number\n");
printf("(1 through 96) will be correct only if x and y are used.\n");

} /* printhelp() */



/* Returns node number in F2 lattice, or 0 if universal arrow didn't
   match all cases */
long omlFind(vstring wffPol)
{

  vstring trialWff = "";
  long i, j, omlNodeNum, trialResult;
  omlNodeNum = 0; /* Initialize to avoid compiler warning */

  if (instr(1, wffPol, chr(UNIV_IMPL)) == 0) {
    /* Normal case */
    omlNodeNum = omlf2(wffPol); /* Run the program - normal run */
  } else {
    /* Special case for universal arrow - try all arrows */
    for (i = 1; i <= 5; i++) {
      let(&trialWff, wffPol);
      for (j = 0; j < strlen(wffPol); j++) {
        if (trialWff[j] == UNIV_IMPL) {
          trialWff[j] = ("I2345")[i - 1];
        }
      }
      trialResult = omlf2(trialWff);
      if (i > 1 && trialResult != omlNodeNum) {
        omlNodeNum = 0;
        break;
      }
      omlNodeNum = trialResult;
      if (!omlNodeNum) break; /* (Used for special applications) */
    }
  }
  let(&trialWff, ""); /* Deallocate */
  return omlNodeNum;
} /* omlFind */


/* Returns equivalent 1 of 96 OM lattice F2 node */
long omlf2(vstring wffPol)
{
  vstring polEqn = "";
  long i, boolCase, omlNodeNum;

  /* Find the ones that pass the Boolean lattice test */
  currentLattice = 1; /* Switch to Boolean lattice */

  /* Find the Boolean case */
  boolCase = -1;
  for (i = 0; i < 16; i++) {
    let(&polEqn, cat("=", wffPol, f2Pol[boolMO2[i][0]], NULL));
    if (test(polEqn)) {
      boolCase = i;
      break;
    }
  }


  if (boolCase == -1) bug(1);

  /* Find the ones that pass the MO2 lattice test */
  currentLattice = 2; /* Switch to MO2 lattice */


  /* Test the 6 possible MO2 cases for the Boolean that matched */
  omlNodeNum = -1;
  for (i = 0; i < 6; i++) {
    if (skipf2[boolMO2[boolCase][i]]) {
      /* Speedup for special applications */
      omlNodeNum = 0;
      continue;
    }
    let(&polEqn, cat("=", wffPol, f2Pol[boolMO2[boolCase][i]], NULL));
    if (test(polEqn)) {
      omlNodeNum = boolMO2[boolCase][i];

      /* Speedup for special applications */
      if (skipf2[omlNodeNum]) omlNodeNum = 0;
      break;
    }
  }
  if (omlNodeNum == -1) bug(2);

  /* Deallocate vstrings */
  let(&polEqn, "");

  return omlNodeNum;
}


void init(void) /* Should be called only once */
{
  long i, j, k;
  vstring tmpStr = "";

  /* vstring initialization */
  for (k = 0; k < MAX_LATTICES; k++) {
    nodeNames[k] = "";
    latticeName[k] = "";
    for (i = 0; i < MAX_NODES; i++) {
      nodeList[k][i] = "";
      for (j = 0; j < MAX_NODES; j++) {
        sup[k][i][j] = "";
      }
    }
  }

  initLattice(1); /* Boolean lattice initialization */
  initLattice(2); /* MO2 lattice initialization */

  /* Initialize canonical F_2 expressions from Beran */
  f2c[1] = "0";  /* 0 0 */ f2[1] = "0";
  f2c[2] = "(x^y)";  /* 1 0 */ f2[2] = "(x^y)";
  f2c[3] = "(x^-y)";  /* 2 0 */ f2[3] = "(x^-y)";
  f2c[4] = "(-x^y)";  /* 3 0 */ f2[4] = "(-x^y)";
  f2c[5] = "-(xvy)";  /* 4 0 */ f2[5] = "(-x^-y)";
  f2c[6] = "((yIx)^x)";  /* 5 0 */ f2[6] = "((x^y)v(x^-y))";
  f2c[7] = "((xIy)^y)";  /* 6 0 */ f2[7] = "((x^y)v(-x^y))";
  f2c[8] = "(x#y)";  /* 7 0 */ f2[8] = "((x^y)v(-x^-y))";
  f2c[9] = "(x#-y)";  /* 8 0 */ f2[9] = "((x^-y)v(-x^y))";
  f2c[10] = "(-y^(y2x))";  /* 9 0 */ f2[10] = "((-x^-y)v(x^-y))";
  f2c[11] = "(-x^(x2y))";  /* 10 0 */ f2[11] = "((-x^-y)v(-x^y))";
  f2c[12] = "(-x5y)";  /* 11 0 */ f2[12] = "(((x^y)v(x^-y))v(-x^y))";
  f2c[13] = "(y5x)";  /* 12 0 */ f2[13] = "(((x^y)v(x^-y))v(-x^-y))";
  f2c[14] = "(x5y)";  /* 13 0 */ f2[14] = "(((-x^-y)v(-x^y))v(x^y))";
  f2c[15] = "(x5-y)";  /* 14 0 */ f2[15] = "(((-x^-y)v(-x^y))v(x^-y))";
  f2c[16] = "(y5(xIy))";  /* 15 0 */ f2[16] = "(((x^y)v(x^-y))v((-x^y)v(-x^-y)))";
  f2c[17] = "(-(y5x)^x)";  /* 0 1 */ f2[17] = "((x^(-xvy))^(-xv-y))";
  f2c[18] = "-(xI-y)";  /* 1 1 */ f2[18] = "(x^(-xvy))";
  f2c[19] = "-(xIy)";  /* 2 1 */ f2[19] = "(x^(-xv-y))";
  f2c[20] = "-(y4x)";  /* 3 1 */ f2[20] = "((-x^y)v((x^(-xv-y))^(-xvy)))";
  f2c[21] = "-(-x3y)";  /* 4 1 */ f2[21] = "((-x^-y)v((x^(-xvy))^(-xv-y)))";
  f2c[22] = "x";  /* 5 1 */ f2[22] = "x";
  f2c[23] = "((xI-y)Iy)";  /* 6 1 */ f2[23] = "((-xvy)^(xv(-x^y)))";
  f2c[24] = "((-xvy)^(y2x))";  /* 7 1 */ f2[24] = "((-xvy)^(xv(-x^-y)))";
  f2c[25] = "(-(x^y)^(-xIy))";  /* 8 1 */ f2[25] = "((-xv-y)^(xv(-x^y)))";
  f2c[26] = "((xIy)I-y)";  /* 9 1 */ f2[26] = "((-xv-y)^(xv(-x^-y)))";
  f2c[27] = "(x3-(yIx))";  /* 10 1 */ f2[27] = "(((-xv-y)^(-xvy))^((xv(-x^-y))v(-x^y)))";
  f2c[28] = "(-xIy)";  /* 11 1 */ f2[28] = "(xv(-x^y))";
  f2c[29] = "(y2x)";  /* 12 1 */ f2[29] = "(xv(-x^-y))";
  f2c[30] = "(x3y)";  /* 13 1 */ f2[30] = "((-xvy)^((xv(-x^-y))v(-x^y)))";
  f2c[31] = "(x3-y)";  /* 14 1 */ f2[31] = "((-xv-y)^((xv(-x^y))v(-x^-y)))";
  f2c[32] = "((x5y)vx)";  /* 15 1 */ f2[32] = "((xv(-x^y))v(-x^-y))";
  f2c[33] = "(-(x5y)^y)";  /* 0 2 */ f2[33] = "((y^(-yvx))^(-yv-x))";
  f2c[34] = "-(yI-x)";  /* 1 2 */ f2[34] = "(y^(-yvx))";
  f2c[35] = "-(x4y)";  /* 2 2 */ f2[35] = "((x^-y)v((y^(-yv-x))^(-yvx)))";
  f2c[36] = "-(yIx)";  /* 3 2 */ f2[36] = "(y^(-yv-x))";
  f2c[37] = "-(-y3x)";  /* 4 2 */ f2[37] = "((-x^-y)v((y^(-yvx))^(-yv-x)))";
  f2c[38] = "((yI-x)Ix)";  /* 5 2 */ f2[38] = "((xv-y)^(yv(-y^x)))";
  f2c[39] = "y";  /* 6 2 */ f2[39] = "y";
  f2c[40] = "((xv-y)^(x2y))";  /* 7 2 */ f2[40] = "((xv-y)^(yv(-y^-x)))";
  f2c[41] = "(-(x^y)^(-yIx))";  /* 8 2 */ f2[41] = "((-xv-y)^(yv(-y^x)))";
  f2c[42] = "(y3-(xIy))";  /* 9 2 */ f2[42] = "(((-xv-y)^(xv-y))^((yv(-x^-y))v(x^-y)))";
  f2c[43] = "((yIx)I-x)";  /* 10 2 */ f2[43] = "((-xv-y)^(yv(-y^-x)))";
  f2c[44] = "(-yIx)";  /* 11 2 */ f2[44] = "(yv(-y^x))";
  f2c[45] = "(y3x)";  /* 12 2 */ f2[45] = "((xv-y)^((yv(-y^-x))v(-y^x)))";
  f2c[46] = "(x2y)";  /* 13 2 */ f2[46] = "(yv(-y^-x))";
  f2c[47] = "(y3-x)";  /* 14 2 */ f2[47] = "((-xv-y)^((yv(-y^x))v(-y^-x)))";
  f2c[48] = "((y5x)vy)";  /* 15 2 */ f2[48] = "((yv(-y^x))v(-y^-x))";
  f2c[49] = "-((y5x)vy)";  /* 0 3 */ f2[49] = "((-y^(yv-x))^(yvx))";
  f2c[50] = "-(y3-x)";  /* 1 3 */ f2[50] = "((x^y)v((-y^(yv-x))^(yvx)))";
  f2c[51] = "-(x2y)";  /* 2 3 */ f2[51] = "(-y^(yvx))";
  f2c[52] = "-(y3x)";  /* 3 3 */ f2[52] = "((-x^y)v((-y^(yvx))^(yv-x)))";
  f2c[53] = "-(-yIx)";  /* 4 3 */ f2[53] = "(-y^(yv-x))";
  f2c[54] = "((x2y)Ix)";  /* 5 3 */ f2[54] = "((xvy)^(-yv(y^x)))";
  f2c[55] = "((xI-y)4y)";  /* 6 3 */ f2[55] = "(((xvy)^(-xvy))^((-yv(x^y))v(-x^y)))";
  f2c[56] = "((-xvy)^(yIx))";  /* 7 3 */ f2[56] = "((-xvy)^(-yv(y^x)))";
  f2c[57] = "((xvy)^(yI-x))";  /* 8 3 */ f2[57] = "((xvy)^(-yv(y^-x)))";
  f2c[58] = "-y";  /* 9 3 */ f2[58] = "-y";
  f2c[59] = "((-yIx)I-x)";  /* 10 3 */ f2[59] = "((-xvy)^(-yv(y^-x)))";
  f2c[60] = "(-y3x)";  /* 11 3 */ f2[60] = "((xvy)^((-yv(y^-x))v(y^x)))";
  f2c[61] = "(yIx)";  /* 12 3 */ f2[61] = "(-yv(y^x))";
  f2c[62] = "(x4y)";  /* 13 3 */ f2[62] = "((-xvy)^((-yv(y^-x))v(y^x)))";
  f2c[63] = "(yI-x)";  /* 14 3 */ f2[63] = "(-yv(y^-x))";
  f2c[64] = "((x5y)v-y)";  /* 15 3 */ f2[64] = "((-yv(y^-x))v(y^x))";
  f2c[65] = "(-(x5y)^-x)";  /* 0 4 */ f2[65] = "((-x^(xv-y))^(xvy))";
  f2c[66] = "-(x3-y)";  /* 1 4 */ f2[66] = "((x^y)v((-x^(xv-y))^(xvy)))";
  f2c[67] = "-(x3y)";  /* 2 4 */ f2[67] = "((x^-y)v((-x^(xvy))^(xv-y)))";
  f2c[68] = "-(y2x)";  /* 3 4 */ f2[68] = "(-x^(xvy))";
  f2c[69] = "-(-xIy)";  /* 4 4 */ f2[69] = "(-x^(xv-y))";
  f2c[70] = "-(x3-(yIx))";  /* 5 4 */ f2[70] = "(((xvy)^(xv-y))^((-xv(x^y))v(x^-y)))";
  f2c[71] = "((y2x)Iy)";  /* 6 4 */ f2[71] = "((xvy)^(-xv(x^y)))";
  f2c[72] = "((xv-y)^(xIy))";  /* 7 4 */ f2[72] = "((xv-y)^(-xv(x^y)))";
  f2c[73] = "((xvy)^(xI-y))";  /* 8 4 */ f2[73] = "((xvy)^(-xv(x^-y)))";
  f2c[74] = "((-xIy)I-y)";  /* 9 4 */ f2[74] = "((xv-y)^(-xv(x^-y)))";
  f2c[75] = "-x";  /* 10 4 */ f2[75] = "-x";
  f2c[76] = "(-x3y)";  /* 11 4 */ f2[76] = "((xvy)^((-xv(x^-y))v(x^y)))";
  f2c[77] = "(y4x)";  /* 12 4 */ f2[77] = "((xv-y)^((-xv(x^y))v(x^-y)))";
  f2c[78] = "(xIy)";  /* 13 4 */ f2[78] = "(-xv(x^y))";
  f2c[79] = "(xI-y)";  /* 14 4 */ f2[79] = "(-xv(x^-y))";
  f2c[80] = "((y5x)v-x)";  /* 15 4 */ f2[80] = "((-xv(x^-y))v(x^y))";
  f2c[81] = "-(x5(yIx))";  /* 0 5 */ f2[81] = "(((xvy)^(xv-y))^((-xvy)^(-xv-y)))";
  f2c[82] = "-(x5-y)";  /* 1 5 */ f2[82] = "(((xvy)^(xv-y))^(-xvy))";
  f2c[83] = "-(x5y)";  /* 2 5 */ f2[83] = "(((xvy)^(xv-y))^(-xv-y))";
  f2c[84] = "-(y5x)";  /* 3 5 */ f2[84] = "(((-xv-y)^(-xvy))^(xvy))";
  f2c[85] = "-(-x5y)";  /* 4 5 */ f2[85] = "(((-xv-y)^(-xvy))^(xv-y))";
  f2c[86] = "(-(x2y)vx)";  /* 5 5 */ f2[86] = "((xvy)^(xv-y))";
  f2c[87] = "(-(y2x)vy)";  /* 6 5 */ f2[87] = "((xvy)^(-xvy))";
  f2c[88] = "-(x#-y)";  /* 7 5 */ f2[88] = "((-xvy)^(xv-y))";
  f2c[89] = "-(x#y)";  /* 8 5 */ f2[89] = "((xvy)^(-xv-y))";
  f2c[90] = "-((xIy)^y)";  /* 9 5 */ f2[90] = "((-xv-y)^(xv-y))";
  f2c[91] = "-((yIx)^x)";  /* 10 5 */ f2[91] = "((-xv-y)^(-xvy))";
  f2c[92] = "(xvy)";  /* 11 5 */ f2[92] = "(xvy)";
  f2c[93] = "(xv-y)";  /* 12 5 */ f2[93] = "(xv-y)";
  f2c[94] = "(-xvy)";  /* 13 5 */ f2[94] = "(-xvy)";
  f2c[95] = "-(x^y)";  /* 14 5 */ f2[95] = "(-xv-y)";
  f2c[96] = "1";  /* 15 5 */ f2[96] = "1";

  /* Pre-compute Polish version for speed-up (when this program is
     used as a subprogram of another) */
  for (i = 1; i <= 96; i++) {
    f2Pol[i] = toPolish(f2[i]);
    skipf2[i] = 0; /* Also initialize the skip flags here */
  }

  /* Map each Boolean case to the 6 possible MO2 cases for it */
  /* The first MO2 case (2nd index 0) is the fastest to compute. */
  boolMO2[0][0] = 1; boolMO2[0][1] = 17; boolMO2[0][2] = 33;
      boolMO2[0][3] = 49; boolMO2[0][4] = 65; boolMO2[0][5] = 81;
  boolMO2[1][0] = 2; boolMO2[1][1] = 18; boolMO2[1][2] = 34;
      boolMO2[1][3] = 50; boolMO2[1][4] = 66; boolMO2[1][5] = 82;
  boolMO2[2][0] = 3; boolMO2[2][1] = 19; boolMO2[2][2] = 35;
      boolMO2[2][3] = 51; boolMO2[2][4] = 67; boolMO2[2][5] = 83;
  boolMO2[3][0] = 4; boolMO2[3][1] = 20; boolMO2[3][2] = 36;
      boolMO2[3][3] = 52; boolMO2[3][4] = 68; boolMO2[3][5] = 84;
  boolMO2[4][0] = 5; boolMO2[4][1] = 21; boolMO2[4][2] = 37;
      boolMO2[4][3] = 53; boolMO2[4][4] = 69; boolMO2[4][5] = 85;
  boolMO2[5][0] = 22; boolMO2[5][1] = 6; boolMO2[5][2] = 38;
      boolMO2[5][3] = 54; boolMO2[5][4] = 70; boolMO2[5][5] = 86;
  boolMO2[6][0] = 39; boolMO2[6][1] = 7; boolMO2[6][2] = 23;
      boolMO2[6][3] = 55; boolMO2[6][4] = 71; boolMO2[6][5] = 87;
  boolMO2[7][0] = 88; boolMO2[7][1] = 8; boolMO2[7][2] = 24;
      boolMO2[7][3] = 40; boolMO2[7][4] = 56; boolMO2[7][5] = 72;
  boolMO2[8][0] = 89; boolMO2[8][1] = 9; boolMO2[8][2] = 25;
      boolMO2[8][3] = 41; boolMO2[8][4] = 57; boolMO2[8][5] = 73;
  boolMO2[9][0] = 58; boolMO2[9][1] = 10; boolMO2[9][2] = 26;
      boolMO2[9][3] = 42; boolMO2[9][4] = 74; boolMO2[9][5] = 90;
  boolMO2[10][0] = 75; boolMO2[10][1] = 11; boolMO2[10][2] = 27;
      boolMO2[10][3] = 43; boolMO2[10][4] = 59; boolMO2[10][5] = 91;
  boolMO2[11][0] = 92; boolMO2[11][1] = 12; boolMO2[11][2] = 28;
      boolMO2[11][3] = 44; boolMO2[11][4] = 60; boolMO2[11][5] = 76;
  boolMO2[12][0] = 93; boolMO2[12][1] = 13; boolMO2[12][2] = 29;
      boolMO2[12][3] = 45; boolMO2[12][4] = 61; boolMO2[12][5] = 77;
  boolMO2[13][0] = 94; boolMO2[13][1] = 14; boolMO2[13][2] = 30;
      boolMO2[13][3] = 46; boolMO2[13][4] = 62; boolMO2[13][5] = 78;
  boolMO2[14][0] = 95; boolMO2[14][1] = 15; boolMO2[14][2] = 31;
      boolMO2[14][3] = 47; boolMO2[14][4] = 63; boolMO2[14][5] = 79;
  boolMO2[15][0] = 96; boolMO2[15][1] = 16; boolMO2[15][2] = 32;
      boolMO2[15][3] = 48; boolMO2[15][4] = 64; boolMO2[15][5] = 80;

  /* Initialize speedup table for negative */
  for (i = 'A'; i <= 'z'; i++) {
    if (isupper(i)) negMap[i] = tolower(i);
    if (islower(i)) negMap[i] = toupper(i);
  }
  negMap['0'] = '1';
  negMap['1'] = '0';

  /* Initialize speedup table for operator */
  for (i = 1; i < 256; i++) {
    if (instr(1, BIN_OPERS, chr(i)) != 0) {
      opMap[i] = 1;
    } else {
      opMap[i] = 0;
    }
    let(&tmpStr, ""); /* Deallocate temporary stack to prevent overflow */
  }

} /* init */

void initLattice(long latticeNum)
{
  /* 1 = Boolean lattice, 2 = MO2 lattice */
  long i ,j ,k, p, q, changed;
  vstring nname = "";
  vstring nbranch = "";
  vstring big = "";
  vstring small1 = "";
  vstring small2 = "";
  vstring oldsup = "";

  switch (latticeNum) {
    case 1:
      nodes[latticeNum] = 2;
      /* Each entry is name of node, followed by nodes directly under it.
         Capital letters are primed versions of lower case letters */
      let(&(latticeName[latticeNum]), "Boolean");
      let(&(nodeList[latticeNum][1]), "10");
      let(&(nodeList[latticeNum][2]), "0");
      break;
    case 2:
      nodes[latticeNum] = 6;
      /* Each entry is name of node, followed by nodes directly under it.
         Capital letters are primed versions of lower case letters */
      let(&(latticeName[latticeNum]), "MO2 (orthomodular)");
      let(&(nodeList[latticeNum][1]), "1ABab");
      let(&(nodeList[latticeNum][2]), "a0");
      let(&(nodeList[latticeNum][3]), "b0");
      let(&(nodeList[latticeNum][4]), "A0");
      let(&(nodeList[latticeNum][5]), "B0");
      let(&(nodeList[latticeNum][6]), "0");
      break;
  } /* switch latticeNum */


   /* Node name list */
   let(&(nodeNames[latticeNum]), "");
   for (i = 1; i <= nodes[latticeNum]; i++) {
     let(&(nodeNames[latticeNum]), cat(nodeNames[latticeNum],
         left(nodeList[latticeNum][i], 1), NULL));
     /* Initialize lookup table */
     nodeNameMap[latticeNum][ascii_(left(nodeList[latticeNum][i], 1))] = i;
   }

   /* Fill out ordering table */
   changed = 1;
   while (changed) {
     changed = 0;
     for (i = 1; i <= nodes[latticeNum]; i++) {
       for (j = 1; j <= nodes[latticeNum]; j++) {
         if (i != j) {
           let(&nname, left(nodeList[latticeNum][j], 1));
           p = instr(2, nodeList[latticeNum][i], nname);
           if (p != 0) {
             for (k = 2; k <= len(nodeList[latticeNum][j]); k++) {
               let(&nbranch, mid(nodeList[latticeNum][j], k, 1));
               q = instr(2, nodeList[latticeNum][i], nbranch);
               if (q == 0) {
                 changed = 1;
                 let(&(nodeList[latticeNum][i]), cat(nodeList[latticeNum][i],
                     nbranch, NULL));
               } /* end if */
             } /* next k */
           } /* end if */
         } /* end if */
       } /* next j */
     } /* next i */
   } /* next while */

   /* Build supremum (disjunction) table */
   for (i = 1; i <= nodes[latticeNum]; i++) {
     for (j = 1; j <= nodes[latticeNum]; j++) {
       let(&(sup[latticeNum][i][j]), "1");
     } /* next j */
   } /* next i */
   for (i = 1; i <= nodes[latticeNum]; i++) {
     let(&big, left(nodeList[latticeNum][i], 1));
     for (j = 1; j <= len(nodeList[latticeNum][i]); j++) {
       for (k = 1; k <= len(nodeList[latticeNum][i]); k++) {
         let(&small1, mid(nodeList[latticeNum][i], j, 1));
         let(&small2, mid(nodeList[latticeNum][i], k, 1));
         let(&oldsup, sup[latticeNum]
             [instr(1, nodeNames[latticeNum], small1)]
             [instr(1, nodeNames[latticeNum], small2)]);
         /* oldsup > big */
         if (instr(2, nodeList[latticeNum]
             [instr(1, nodeNames[latticeNum], oldsup)], big)) {
           let(&(sup[latticeNum][instr(1, nodeNames[latticeNum], small1)]
               [instr(1, nodeNames[latticeNum], small2)]), big);
         } /* end if */
       } /* next k */
     } /* next j */
   } /* next i */

   /* Debug */
   /*
   for (i = 1; i <= nodes[latticeNum]; i++) {
     for (j= 1; j <= nodes[latticeNum]; j++) {
       printf("%s",sup[latticeNum][i][j]);
     }
     printf("\n");
   }
   */

  /* Deallocate vstrings */
  let(&nname, "");
  let(&nbranch, "");
  let(&big, "");
  let(&small1, "");
  let(&small2, "");
  let(&oldsup, "");

} /* initLattice() */

/* Returns 1 if matrix test passed, 0 if failed */
char test(vstring polEqn)
{
  long n, x, y, p, e;
  vstring trialEqn = "";
  e = 0; /* Initialize to avoid compiler warning */
  /* Perform all possible evaluations */
  n = strlen(polEqn);
  for (x = 0; x < nodes[currentLattice]; x++) {
    for (y = 0; y < nodes[currentLattice]; y++) {
      let(&trialEqn, polEqn);
      for (p = 0; p < n; p++) {
        switch (polEqn[p]) {
          case 'x':
            trialEqn[p] = nodeNames[currentLattice][x];
            break;
          case 'y':
            trialEqn[p] = nodeNames[currentLattice][y];
            break;
        }
      }
      e = eval(trialEqn);
      if (e != '1') goto done; /* Failed */
    }
  }
 done:
  if (e != '1') {
    return 0;
  } else {
    return 1;
  }
} /* test() */

/* Returns the char value of the nodeName character that the
   trial equation evaluates to */
char eval(vstring trialEqn)
{
  char e;
  vstring subEqn1 = "";
  vstring subEqn2 = "";

  if (trialEqn[0] == NEG_OPER) {
    let(&subEqn1, right(trialEqn, 2));
    e = lookupCompl(eval(subEqn1));
  } else {
    if (instr(1, BIN_OPERS, chr(trialEqn[0])) != 0) {
      subEqn1 = subFormula(right(trialEqn, 2));
      subEqn2 = subFormula(right(trialEqn, strlen(subEqn1) + 2));
      e = lookupBinOp(trialEqn[0], eval(subEqn1), eval(subEqn2));
    } else {
      /* Must be a node */
      e = trialEqn[0];
    }
  }
  let(&subEqn1, "");  /* Deallocate vstring */
  let(&subEqn2, "");  /* Deallocate vstring */
  return e;

}

char lookupCompl(char arg) {
  /* abc... = node names; ABC.. = complemented node names */
  /*
  if (arg == '0') return '1';
  if (arg == '1') return '0';
  if (isupper(arg)) return tolower(arg);
  if (islower(arg)) return toupper(arg);
  bug(3);
  return 0;
  */
  /* Speedup */
  return negMap[(long)arg];
}

char lookupBinOp(char operation, char arg1, char arg2) {
    /*
    ^ = conjunction
    v = disjunction
    # = biimplication: ((x^y)v(-x^-y))
    < = less-than-or-equal operator:  ((xvy)=y)
    O = ->0 = classical arrow: (-xvy)
    I = ->1 = Sasaki arrow: (-xv(x^y))
    2 = ->2 = Dishkant arrow: (-yI-x)
    3 = ->3 = Kalmbach arrow: (((-x^y)v(-x^-y))v(x^(-xvy)))
    4 = ->4 = non-tollens arrow: (-y3-x)
    5 = ->5 = relevance arrow: (((x^y)v(-x^y))v(-x^-y))
    */
  switch (operation) {
    case 'v':
      /*
      return (sup[currentLattice][instr(1, nodeNames[currentLattice],
           chr(arg1))]
          [instr(1, nodeNames[currentLattice], chr(arg2))])[0];
      */
      /* Speedup */
      return (
          sup[currentLattice][(long)(nodeNameMap[currentLattice][(long)arg1])]
          [(long)(nodeNameMap[currentLattice][(long)arg2])])[0];
    case '^':
      return lookupCompl(lookupBinOp('v', lookupCompl(arg1),
          lookupCompl(arg2)));
    case '=': /* For compatibility with old program version */
    case '#':
      return lookupBinOp('v',
                lookupBinOp('^', arg1, arg2),
                lookupCompl(lookupBinOp('v', arg1, arg2)));
    case '<':
      return lookupBinOp('=', lookupBinOp('v', arg1, arg2), arg2);
    case 'O':
      return lookupBinOp('v', lookupCompl(arg1), arg2);
    case 'I':
      return lookupBinOp('v', lookupCompl(arg1),
                lookupBinOp('^', arg1, arg2));
    case '2':
      return lookupBinOp('I', lookupCompl(arg2), lookupCompl(arg1));
    case '3':
      return lookupBinOp('v',
               lookupBinOp('v',
                 lookupBinOp('^', lookupCompl(arg1), arg2),
                 lookupBinOp('^', lookupCompl(arg1), lookupCompl(arg2))),
               lookupBinOp('^', arg1,
                 lookupBinOp('v', lookupCompl(arg1), arg2)));
    case '4':
      return lookupBinOp('3', lookupCompl(arg2), lookupCompl(arg1));
    case '5':
      return lookupBinOp('v',
               lookupBinOp('v',
                 lookupBinOp('^', arg1, arg2),
                 lookupBinOp('^', lookupCompl(arg1), arg2)),
               lookupBinOp('^', lookupCompl(arg1), lookupCompl(arg2)));
  } /* switch (operation) */
  bug(4);
  return 0;
}

/* Returns the shortest subformula from beginning of equation */
/* The caller must deallocate the result */
vstring subFormula(vstring eqn)
{
  vstring result = "";
  long i, p;
  let(&result, eqn); /* In case temp allocation passed in */
  i = 0;
  p = 1;
  while (p > 0) {
    /*
    if (instr(1, BIN_OPERS, chr(result[i])) != 0) {
    */
    /* Speedup */
    if (opMap[(long)(result[i])]) {
      p++;
    } else {
      if (result[i] != NEG_OPER) p--; /* It is a node name */
    }
    i++;
  }
  let(&result, left(result, i));
  return result;
}


/* ***Note:  The caller must deallocate returned string */
/* Convert normal to Polish notation */
vstring toPolish(vstring equation)
{
 /* This function converts a theorem in parentheses notation to
    one in Polish notation */

  vstring stack[MAX_STACK];
  long i, stackPtr, stackTop, level, p;
  vstring stackEntry = "";
  vstring polEqn = "";

  /* Initialize vstring array */
  /* Done below only as needed for speedup
  for (i = 0; i < MAX_STACK; i++) {
    stack[i] = "";
  }
  */

  stackPtr = 1;
  stackTop = 1;
  stack[stackTop] = ""; /* Initialize vstring array */
  let(&(stack[stackPtr]), equation);
  while (stackPtr <= stackTop) {
    let(&stackEntry, stack[stackPtr]);

    if (len(stackEntry) == 1) {
      /* The stack entry is a single character.  Only a variable
         or constant is allowed. */
      if (instr(1, "xy01", stackEntry) == 0) {
        printf("%s\n", cat("?Error #1 - Bad syntax in ",
            equation, NULL));
        exit(0);
      } /* end if */
      stackPtr++;
    } else { /* 1 */

    if (stackEntry[0] == NEG_OPER) {  /* Negation */
      if (stackTop >= MAX_STACK - 1) {
        printf(
            "?Error #2 - Stack overflow - please increase MAX_STACK\n");
        exit(0);
      }
      stackTop++;
      stack[stackTop] = ""; /* Initialize vstring array */
      for (i = stackTop - 1; i >= stackPtr + 1; i--) { /* Push stack */
        let(&(stack[i + 1]), stack[i]);
      }
      let(&(stack[stackPtr]), chr(NEG_OPER));
      let(&(stack[stackPtr + 1]), right(stackEntry, 2));
      stackPtr++;
    } else { /* 2 */

    if (stackEntry[0] == '(') {  /* 2-argument operator */
      if (stackTop >= MAX_STACK - 2) {
        printf(
            "?Error #3 - Stack overflow - please increase MAX_STACK\n");
        exit(0);
      }
      stackTop++;
      stack[stackTop] = ""; /* Initialize vstring array */
      stackTop++;
      stack[stackTop] = ""; /* Initialize vstring array */
      for (i = stackTop - 2; i >= stackPtr + 1; i--) {
        /* Push stack */
        let(&(stack[i + 2]), stack[i]);
      }
      if (stackEntry[strlen(stackEntry) - 1] != ')') {
        printf("%s\n", cat("?Error #4 - Bad syntax in ",
            equation, NULL));
        exit(0);
      } /* end if */
      /* Find the operator */
      level = 0;
      p = 2;
      while (stackEntry[p - 1] == NEG_OPER) p++; /* Get past negations */

      if (stackEntry[p - 1] == '(') { /* Find closing parenthesis */
        level = 1;
        while (level > 0 && p < strlen(stackEntry)) {
          p++;
          if (stackEntry[p - 1] == '(') level++;
          else
            if (stackEntry[p - 1] == ')') level--;
        } /* end while */
      }
      p++;
      if (instr(1, BIN_OPERS, mid(stackEntry, p, 1)) == 0 ||
          p > strlen(stackEntry)) {
        printf("%s\n", cat("?Error #5 - Bad syntax in ",
            equation, NULL));
        exit(0);
      } /* end if */
      let(&(stack[stackPtr]), mid(stackEntry, p, 1));
      let(&(stack[stackPtr + 1]), seg(stackEntry, 2, p - 1));
      let(&(stack[stackPtr + 2]), seg(stackEntry, p + 1,
          strlen(stackEntry) - 1));
      stackPtr++;
    } else { /* 3 */
       printf("%s\n", cat("?Error #6 - Bad syntax in ",
           equation, NULL));
       exit(0);
    } } } /* 3 2 1 */
  } /* end while */

  for (i = 1; i <= stackTop; i++) {
    let(&polEqn, cat(polEqn, stack[i], NULL));
    let(&(stack[i]), ""); /* Deallocate vstring array */
  }

  return polEqn;

} /* toPolish */



/*****************************************************************************/
/*       Copyright (C) 1998  NORMAN D. MEGILL  <nm@alum.mit.edu>             */
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
'le(&t' function is next executed.  For example,

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
          printf("%s\n",left(string1,70));

will allocate another 70 bytes or so of memory each pass through the loop.
If necessary, dummy 'let(&' assignments can be made periodically to clear
this temporary memory:

        for (i=0; i<10000; i++)
          {
          printf("%s\n",left(string1,70));
          let(&dummy,"");
          }

It should be noted that the 'linput' function assigns its target string
with 'let(&' and thus has the same effect as 'let(&'.

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
      printf("*** FATAL ERROR ***  Temporary string stack overflow\n");
      bug(2201);
    }
    if (!(tempAllocStack[tempAllocStackTop++]=malloc(size))) {
      printf("*** FATAL ERROR ***  Temporary string allocation failed\n");
      bug(2202);
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
      printf("*** FATAL ERROR ***  Temporary string stack overflow\n");
      bug(2203);
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
          printf("*** FATAL ERROR ***  String memory couldn't be allocated\n");
          bug(2204);
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
        printf("*** FATAL ERROR ***  Could not allocate string memory\n");
        bug(2205);
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
      printf("*** FATAL ERROR ***  Too many cat() arguments\n");
      bug(2206);
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
  if (ask) printf("%s",ask);
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
#define isblank(c) ((c==' ') || (c=='\t'))
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
    while ((sout[i]!=0) && isblank(sout[i]))
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
    if ((alldiscard_flag) && isblank(sout[i]))
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
    while ((k>=0) && isblank(sout[k])) --k;
    sout[++k]=0;
  }

  /* Reduce multiple space/tab to a single space */
  if (reduce_flag) {
    i=j=last_char_is_blank=0;
    while (i<=k-1) {
      if (!isblank(sout[i])) {
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
  return ((long)c[0]);
}

/* Returns the floating-point value of a numeric string */
double val(vstring s)
{
  return (atof(s));
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
  s=tempAlloc(50);
  sprintf(s,"%f",f);
  if (strchr(s,'.')!=0) {               /* the string has a period in it */
    for (i=strlen(s)-1; i>0; i--) {     /* scan string backwards */
      if (s[i]!='0') break;             /* 1st non-zero digit */
      s[i]=0;                           /* delete the trailing 0 */
    }
    if (s[i]=='.') s[i]=0;              /* delete trailing period */
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


/* Bug check */
void bug(int bugNum)
{
  printf("?Error - program bug # %d\n", bugNum);
  exit(0);
}
