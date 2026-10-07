> module Main where
> 
> import HghCore
>
> import System.Exit
> 
> import Test.HUnit.Base
> import Test.HUnit.Text
> 
> main :: IO ()
> main = do
>	Counts {errors=e, failures=f} <- runTestTT testCases
>	case e+f of
>		0 -> return ()
>		_ -> exitWith (ExitFailure 1)
> 
> 
> testCases :: Test
> testCases =
>	TestList
>	[




>	"simple data structure tests" ~: test
>	[Var "x" @?= Var "x"

>	,mkInferenceRule (mkDVRSet []) [] (Var "P")
>		@?= mkInferenceRule (mkDVRSet []) [] (Var "P")
>	,mkInferenceRule (mkDVRSet [("P","Q")]) [] (Var "P")
>		@?= mkInferenceRule (mkDVRSet [("Q","P")]) [] (Var "P")

>	,Hypothesis (Var "P") @?= Hypothesis (Var "P")
>	,RuleApp [] [Var "Q"] (mkInferenceRule (mkDVRSet []) [] (Var "P"))
>		@?= RuleApp [] [Var "Q"] (mkInferenceRule (mkDVRSet []) [] (Var "P"))

>	,interpretProof2 (Hypothesis (Var "P"))
>		@?= Right ([], mkInferenceRule (mkDVRSet []) [(Var "P")] (Var "P"))

>	,interpretProof2
>			(RuleApp
>			[Hypothesis $ Var "Q"]
>			[] (trivial $ Var "P")
>			)
>		@?= Right ([trivial $ Var "P"], trivial $ Var "Q")

>	,interpretProof2
>			(RuleApp
>			[Hypothesis (App "<->" [Var "G", Var "H"])]
>			[Var "F"] leibniz_equiv_rightOr
>			)
>		@?= Right ([leibniz_equiv_rightOr], leibniz_equiv_rightOr)

The first really useful proof::

>	,interpretProof2
>			(RuleApp
>			[Hypothesis (App "\\/" [Var "F", Var "G"])
>			,	RuleApp
>				[Hypothesis (App "<->" [Var "G", Var "H"])]
>				[Var "F"] leibniz_equiv_rightOr
>			]
>			[] inf1a_top
>			)
>		@?= Right ([inf1a_top, leibniz_equiv_rightOr], inf1a_rightOr)
>			--TODO: make sure that order/duplicates of hypotheses
>			--are not important

TODO: Check the stuff from the Appendix.

>	]
>	]

> trivial :: Expression -> InferenceRule
> trivial expr = mkInferenceRule (mkDVRSet []) [expr] expr

> leibniz_equiv_rightOr :: InferenceRule
> leibniz_equiv_rightOr = mkInferenceRule
>				(mkDVRSet [])
>				[App "<->" [Var "G", Var "H"]]
>				(App "<->"
>					[App "\\/" [Var "F", Var "G"]
>					,App "\\/" [Var "F", Var "H"]
>					])

> inf1a_top :: InferenceRule
> inf1a_top = mkInferenceRule
>				(mkDVRSet [])
>				[Var "G"
>				,App "<->" [Var "G", Var "H"]
>				]
>				(Var "H")

> inf1a_rightOr :: InferenceRule
> inf1a_rightOr = mkInferenceRule
>				(mkDVRSet [])
>				[App "\\/" [Var "F", Var "G"]
>				,App "<->" [Var "G", Var "H"]
>				]
>				(App "\\/" [Var "F", Var "H"])

> interpretProof2 :: Proof -> Either String ([InferenceRule], InferenceRule)
> interpretProof2 proof = case interpretProof proof of
>				Left errorMessage -> Left errorMessage
>				Right d -> Right (sourceRules d, targetRule d)

