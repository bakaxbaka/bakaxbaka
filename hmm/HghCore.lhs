A Haskell module for sound Ghilbert-style proofs
================================================

:Author: Marnix Klooster <marnix.klooster@gmail.com>
:Copyright: GPL version 2 or later
:Note: This is a work in progress.  Correctness and completeness not guaranteed.
	You have been warned!

(This document is usually available in two formats: `XHTML <HghCore.xhtml>`__
and `literate Haskell <HghCore.lhs>`__.)

Introduction
------------

Here is the suggested interface for a small Haskell module that implements the
Ghilbert-based core proof language, which I suggested to Raph Levien (personal
e-mail, 30 May 2006).
This module could be the core of a Ghilbert verifier::

> module HghCore

Some understanding of Metamath and/or Ghilbert is useful, but this document is
intended to be reasonably self-contained.

The code in this document has been tested under GHC 6.4.2, but could very well
work with other Haskell systems as well.  To actually make this document work
like a 'literate Haskell module', the order of this document is sometimes
forced a bit.


Overview
--------

This module provides an encapsulated data type ::

>	(Derivation

with accessors ::

>	,sourceRules, targetRule

together with a very limited way of creating values of this type::

>	,interpretProof

This function takes a ::

>	,Proof(Hypothesis, RuleApp)

which is essentially the same as a Ghilbert proof.  ``interpretProof`` then
computes the resulting 'thm' (the 'target inference rule' of the ``Derivation``).
What Ghilbert calls a 'thm' or a 'stmt', we call an ::

>	,InferenceRule, mkInferenceRule, ruleDVRs, ruleHypotheses, ruleConclusion

``interpretProof`` also keeps track of all inference rules that are used by the proof (the
'source inference rules' of the ``Derivation``).

Part of an ``InferenceRule`` is a set of 'disjoint variable restrictions'::

>	,DVRSet, mkDVRSet

All this is based on LISP-like expressions, just like GHilbert::

>	,Expression(Var, App)
>	)
> where

We will need some auxiliary functionality from standard modules::

> import Data.List(sort, nub, (\\))


Expressions and inference rules
-------------------------------

All mathematical expressions are constructed from variables and operators
(=constants)::

> data Expression = Var VarName | App ConstName [Expression]
>	deriving (Eq, Show)

with ::

> type VarName = String
> type ConstName = String

(TODO: Make these into real datatypes, so that we have real typechecking.)

An ``InferenceRule`` represents how to get from source expressions (hypotheses)
to a target expression (the conclusion). ::

> data InferenceRule = InferenceRule
>	{ruleDVRs :: DVRSet
>	,ruleHypotheses :: [Expression]
>	,ruleConclusion :: Expression
>	}
>	deriving (Eq, Show)

(TODO: Create a custom Show instance, so that we more understandable output
during debugging.)

Two ``InferenceRule`` objects are equal (under ``Eq``) iff they have the same
DVRSet, the same hypotheses (in the same order, including potential
duplicates), and the same conclusion.

Note that the constructor for this data type is not exported, so that we can
choose an optimal data structure for performance.  Therefore we need a
very simple constructor function::

> mkInferenceRule :: DVRSet -> [Expression] -> Expression
>			-> InferenceRule
> mkInferenceRule dvrSet hyps concl = InferenceRule dvrSet hyps concl

Here we use the data type ``DVRSet``, for which we only export the type ::

> data DVRSet = DVRSet [(VarName, VarName)]
>	deriving (Eq, Show)

To create a ``DVRSet`` the constructor function ``mkDVRSet`` is used.  This
function makes sure that two DVRSets are equal (under ``Eq``) if they have the
same restrictions, where duplicates are ignored, and ("x","y") is the same as
("y","x").  It does that by keeeping the DVRs in an ``InferenceRule`` in
canonical order, with duplicates removed, and each pair ordered::

> mkDVRSet :: [(VarName, VarName)] -> DVRSet
> mkDVRSet = DVRSet . nub . sort . Prelude.map sortPair
>	where sortPair (p, q)
>		| p <= q = (p, q)
>		| True = (q, p)

Because of the canonical representation of an ``InferenceRule``, the
implementation of ``Eq InferenceRule`` is as simple as "``deriving Eq``" (as is
done above).


Proofs
------

Now on to proofs::

> data Proof
>	= Hypothesis Expression
>	| RuleApp [Proof] [Expression] InferenceRule
>	deriving (Eq, Show)

TODO: Explain what the components of a RuleApp mean, and what it means for a
RuleApp to be consistent.

Design Issue. As written, a ``RuleApp`` requires knowledge of the order of the
hypotheses of an ``InferenceRule``. However, (meta-)logically
``InferenceRule`` values that only differ in their order of hypotheses are
equivalent.  Therefore we have four options.

 * We specify the order of the result of ``ruleHypotheses`` to be the same as
   the creation order.  We declare an ``InferenceRule`` with a different order
   of hypotheses to be different (under ``Eq``).  (We introduce a new
   equivalence ``(<==>)`` on ``InferenceRule``, and by extension on ``Proof``
   and ``Derivation`` (see below).) In a ``RuleApp`` the proofs must be in
   creation order.

 * We specify the order of the result of ``ruleHypotheses`` to be the same as
   the creation order.  Two ``InferenceRule`` objects can have different
   ``ruleHypothese`` results, and still be the same (under ``Eq``).  (This
   seems to be inconsistent.)  In a ``RuleApp`` the proofs must be in creation
   order.

 * We specify the order of the result of ``ruleHypotheses`` to be some
   arbitrary (but consistent) order.  In a ``RuleApp`` the proofs must be
   in this same order.

 * Instead of ``[Proof]``, a ``RuleApp`` uses ``[(Expression, Proof)]``, where
   each ``Expression`` is the hypothesis that is proven by the corresponding
   sub-``Proof``.  (Or we could even have it use a ``(Expression -> Proof)``,
   but that seems a bit silly.)

It seems each of these has its disadvantages.  It seems the first option is the
most consistent, while still making this module easy to use for a Ghilbert
verifier.  That's why I went with that option.  (End of Design Issue.)


Deriving inference rules: Derivations
-------------------------------------

Now we come to the heart of the matter: the ``Derivation``.   A ``Derivation``
says: if these inference rules (the 'source rules') hold, then this inference
rule (the 'target rule') holds as well. ::

> data Derivation = Derivation
>	{sourceRules :: [InferenceRule]
>	,targetRule :: InferenceRule
>	}
>	deriving (Show, Eq) --TODO: implement a correct Eq

We do not export the constructors for the ``Derivation`` datatype, because we
require that only 'true' derivations can be constructed by clients of this
module.  Therefore we will limit the ways in which ``Derivation`` objects can
be created.

As a simple example, from the following two inference rules:

 * for all ``F``, ``G`` and ``H``, if ``G <-> H`` holds, then ``(F \/ G) <-> (F
   \/ H)`` holds

 * for all ``P`` and ``Q``, if both ``P`` and ``P <-> Q`` hold, then ``Q``
   holds

we can derive the following so-called derived inference rule:

 * for all ``F``, ``G``, and ``H``, if both ``F \/ G`` and ``G <-> H`` hold,
   then ``F \/ H`` holds

For now the only function that results in a Derivation is ``interpretProof``::

> interpretProof :: Proof -> Either String Derivation

This function basically implements the Ghilbert proof verification algorithm,
with the DVRs computed just like Hmm does this for Metamath proofs.  
If the ``Proof`` is incorrect (i.e., if a ``RuleApp`` in it is inconsistent),
then the result will be ``Left "some error message"``, otherwise the result
will be a ``Right`` value with the resulting ``Derivation``.

The simplest part of the Ghilbert proof algorithm is handling an
``Hypothesis``::

> interpretProof (Hypothesis expr) =
>	Right $ Derivation
>		{sourceRules = []
>		,targetRule = mkInferenceRule (mkDVRSet []) [expr] expr
>		}

In words: any hypothesis proves the simplest possible inference rule, namely
that from any expression we can derive any expression.

``RuleApp`` is the interesting case::

> interpretProof (RuleApp subproofs varExprs rule)

First we handle the inconsistent uses of ``RuleApp``.  There needs to be
exactly one subproof per rule hypothesis::

>	| length (ruleHypotheses rule) /= length subproofs =
>		Left $ "TODO: nice error message"

TODO: for correctness,

 * check that subderivationsOrErrors has only Right values
 * check that substitutionsOrErrors has only Right values
 * check that substitution has no duplicate keys

If all of the above is correct, then the resulting ``Derivation`` ::

>	| True =
>		Right $ Derivation

has as its source rules, the current inference rule, together with those of
its subderivations::

>			{sourceRules = rule : concat (map sourceRules subderivations)

From the ``RuleApp`` ``Proof`` we can derive that the conclusion of the rule
(after substitution) follows from all hypotheses of all subproofs::

>			,targetRule = let
>				dvrs = mkDVRSet [] --TODO: implement
>				hypotheses = concat $ map (ruleHypotheses . targetRule) subderivations
>				conclusion = substApply substitution (ruleConclusion rule)
>			 in mkInferenceRule dvrs hypotheses conclusion
>			}

In the above we used the following definitions::

>	where
>		subderivationsOrErrors = map interpretProof subproofs
>		subderivations = map (\(Right x) -> x) subderivationsOrErrors
>
>		subconclusions = map (ruleConclusion . targetRule) subderivations
>
>		substitutionsOrErrors :: [Either String Substitution]
>		substitutionsOrErrors = zipWith findSubstitution
>						(ruleHypotheses rule) subconclusions
>
>		substitution :: Substitution
>		substitution = fromRight $ substConcat
>					( Substitution (zip (ruleLocalVars rule) varExprs)
>					: map (\(Right x) -> x) substitutionsOrErrors
>					)
>			--Note that no substitution key duplication is possible
>			--here, so we can use fromRight

Here the 'rule local variables' are those that only occur in its conclusion,
and not in its hypotheses::

> ruleLocalVars :: InferenceRule -> [VarName]
> ruleLocalVars rule =
>	nub (varsOf (ruleConclusion rule))
>	\\ concat (map varsOf (ruleHypotheses rule))

See the appendix for the substitution functions.

This completes the implementation of the proof algorithm.

Two ``Derivation`` objects are equal (under ``Eq``) iff they map the same *set*
of ``InferenceRule`` to the same ``InferenceRule``.  This implies that a
``Derivation`` is independent of the ``Proof`` that was used to create it.

Open Issue. We could also make it possible to combine ``Derivation`` objects::

< combineDerivation :: Derivation -> Derivation -> Derivation

This takes the second derivation, removes from its ``sourceRules`` the
``targetRule`` of the first derivation, and adds to its sourceRules the
``sourceRules`` of the first derivation.  Perhaps it sounds difficult, but
basically this 'clicks together' derivations.

This ``combine`` operator is theoretically not necessary, since it is also
possible to have a similar operator at the ``Proof`` level, and then
``interpretProof`` creates the desired ``Derivation``.  However, this requires
one of the following:

 * Either a client of this module has to remember a ``Proof`` for each
   ``Derivation``;

 * Or this module makes a ``Proof`` part of each ``Derivation``.

Frankly I don't really like any of the three alternatives.  The best
alternative might be the first bullet above: implement the ``combine``
functionality outside of this core module, and keep ``Derivation`` and
``Proof`` separate.  But I haven't decided yet.  (End Open Issue.)


Weakening
---------

Until now we've not been complete, in the technical sense: it is not possible
to create every 'true' ``Derivation`` through ``interpretProof``.  The reason is
that ``interpretProof`` computes the "strongest" inference rule that is proven
by the given Proof.  To do proper theorem verification à la Ghilbert, we need
to be able to weaken a given derivation.

First, to determine the relationship between inference rules, we introduce ::

< (==>) :: InferenceRule -> InferenceRule -> Bool

Basically ``i ==> j`` ("``i`` is at least as strong as ``j``") iff ``i`` and
``j`` have the same conclusion, and if the DVRs and hypotheses of ``i`` are a
subset (under (<==>)) of those of ``j``.

Now we need the following two additional ways to create ``Derivations``::

< strengthenSourceRules :: InferenceRule -> Derivation -> Derivation
< weakenTargetRule :: InferenceRule -> Derivation -> Derivation

``strengthenSourceRule`` adds the given ``InferenceRule`` to the
``sourceRules``, and removes any that are weaker (i.e., implied by it under
(==>)).  ``weakenTargetRule`` replaces the ``targetRule`` by the given
``InferenceRule``, but only if the original rule implies the new one (otherwise
an error occurs).


Appendix: helper functions
--------------------------

This appendix implements auxiliary functionality.

Expressions
~~~~~~~~~~~

The variables occurring in an expression are easily computed::

> varsOf :: Expression -> [VarName]
> varsOf (Var v) = [v]
> varsOf (App _c exprs) = concat $ map varsOf exprs

(Note that we do not remove duplicates here; each caller is responsible for
that.)

Substitutions
~~~~~~~~~~~~~

A substitution describes how to map variables to expressions::

> data Substitution = Substitution [(VarName, Expression)]
>	deriving Show

Apply a substitution is simple::

> substApply :: Substitution -> Expression -> Expression
> substApply s@(Substitution m) (Var v) = case lookup v m of
>				Just expr -> expr
>				Nothing -> error $ "could not find " ++ show v ++ " in " ++ show s
> substApply s (App c exprs) = App c (map (substApply s) exprs)

It is equally simple to find a substitution from one expression to another::

> findSubstitution :: Expression -> Expression -> Either String Substitution
> findSubstitution (Var v) expr = Right $ Substitution [(v, expr)]
> findSubstitution expr1@(App _ _) expr2@(Var _) =
>	Left $ "cannot match " ++ show expr1 ++ " and " ++ show expr2
> findSubstitution expr1@(App c1 exprs1) expr2@(App c2 exprs2)
>	| c1 /= c2 =
>		Left $ "cannot match operators of " ++ show expr1 ++ " and " ++ show expr2
>	| length exprs1 /= length exprs2 =
>		Left $ "different arity in " ++ show expr1 ++ " and " ++ show expr2
>	| not allOk =
>		Left $ "no substitution found from " ++ show expr1 ++ " to " ++ show expr2
>		--TODO: add the Left values from substitutionsOrErrors
>	| True =
>		substitutionOrError
>		--TODO: if Left, add a Left error message saying which substitution is impossible
>	where
>		substitutionsOrErrors = zipWith findSubstitution exprs1 exprs2
>		allOk = allRight substitutionsOrErrors
>		substitutionOrError = substConcat $ map (\(Right x) -> x) substitutionsOrErrors

For now we implement ``substConcat`` in a very simple way::

> substConcat :: [Substitution] -> Either String Substitution
> substConcat = Right . Substitution . concat . map (\(Substitution m) -> m)

TODO: check for key duplication!


Error messages
~~~~~~~~~~~~~~

::

> allRight :: [Either a b] -> Bool
> allRight [] = True
> allRight (Left _ : _) = False
> allRight (Right _ : rest) = allRight rest


Either
~~~~~~

::

> fromRight :: Either a b -> b
> fromRight (Right b) = b
> fromRight (Left _a) = error "cannot apply fromRight to a Left value"
