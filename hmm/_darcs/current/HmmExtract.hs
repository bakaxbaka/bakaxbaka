module Main where

import HmmImpl
import System.Environment(getArgs)

main :: IO ()
main = do
	dbText <- getContents
	[theoremLabel] <- getArgs
	case mmParseFromString dbText of
		Left err -> putStrLn ("Parse error: " ++ err)
		Right (_, db) -> do
			let (_lab, _expr, Theorem _hyps _dvrset proof) = findStatement db theoremLabel
			putStrLn $ toMMProof $ expandProofTree $ toProofTree proof

{-
   TODO: The DVRSets are not taken into account, so some $d statements need to
   be added for the proof to be accepted.  (Or is this because Metamath is stricter
   than hmmverify?)
-}

expandProofTree :: ProofTree Statement -> ProofTree Statement
expandProofTree (Apply (_lab, _expr, Theorem hyps _dvrset proof) subproofs) =
	let
		hypMap = zipWith (\(lab, _, _) subproof -> (lab, subproof))
				hyps
				subproofs
	in expandProofTree (substituteHyps hypMap (toProofTree proof))
expandProofTree (Apply stat subproofs) =
	Apply stat (map expandProofTree subproofs)

substituteHyps :: [(Label, ProofTree Statement)] -> ProofTree Statement -> ProofTree Statement
substituteHyps m (Apply stat subproofs) | isAssertion stat =
	Apply stat (map (substituteHyps m) subproofs)
substituteHyps m proofTree@(Apply (lab, _expr, _info) []) =
	case lookup lab m of
		Just p -> p
		Nothing -> proofTree
substituteHyps _ _ = error "this should not occur"



-- HELPER FUNCTIONS (move to HmmImpl.hs or elsewhere?)

toMMProof :: ProofTree Statement -> String
toMMProof (Apply stat subproofs) = join (map toMMProof subproofs ++ [labelOf stat])

labelOf :: Statement -> String
labelOf (lab, _expr, _info) = lab

join :: [String] -> String
join [] = ""
join [x] = x
join (x:xs) = x ++ " " ++ join xs

toProofTree :: Proof -> ProofTree Statement
toProofTree = fromRight . mmComputeProofTree
