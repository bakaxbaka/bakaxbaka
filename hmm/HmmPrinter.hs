{-
	Initial code for a 'proof printer': show a Metamath proof in a format
	that resembles a calculational proof.

	TODO:

	 - Print out a ProofTree Expression using the following rules: (1)
	   begin with the top level; (2) indentation = number of items on the
	   stack after this proof step.   Make it look like a calculation.

	 - Fold 1-step subproofs into the calculation.

	 - Choose the 'main' subproof not to be the first subproof (= rule (2),
	   above), but the longest one (or other heuristic?).

	 - Show special inference rules ($a/$p statements), like ax-mp, mtbir,
	   etc. in special ways, so that the calculations become nicer.  Preferably
	   automatically based on the content of the $a/$p statement.
	
-}

module HmmPrinter
	(mmPrintTheoremProof
	)

where

import HmmImpl


mmPrintTheoremProof :: Database -> Label -> String
mmPrintTheoremProof db lab = mmPrintProof proof
	where
		stat = findStatement db lab
		(_, _, Theorem _ _ proof) = stat

mmPrintProof :: Proof -> String
mmPrintProof proof = show tree
	where
		tree = onlyExpressions $ onlyEssential $ fromRight $ mmComputeSubtheorems (fromRight $ mmComputeProofTree proof)

onlyEssential :: ProofTree (Statement, Expression, DVRSet) -> ProofTree (Statement, Expression, DVRSet)
onlyEssential (Apply (stat, expr, dvrSet) subtrees) =
	Apply (stat, expr, dvrSet) $ map onlyEssential $ map fst $ filter isEssential $ zip subtrees (getHypotheses stat)
	where
		isEssential :: (ProofTree (Statement, Expression, DVRSet), Statement) -> Bool
		isEssential (_, st) = isDollarE st

onlyExpressions :: ProofTree (Statement, Expression, DVRSet) -> ProofTree Expression
onlyExpressions (Apply (_, expr, _) subtrees) = Apply expr (map onlyExpressions subtrees)
