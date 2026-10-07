module Main where

import Hmm(mmParseFromString, mmVerifiesAll)

main :: IO ()
main = do
	dbText <- getContents
	case mmParseFromString dbText of
		Left err -> putStrLn ("Parse error: " ++ err)
		Right (_, db) ->
			sequence_ $
				map (\(lab, result) ->
					putStrLn (lab ++ ": " ++
						case result of
							Left err -> "INCORRECT: " ++ err
							Right () -> "verified"
					))
					(mmVerifiesAll db)
