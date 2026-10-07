module Main where

import Hmm(mmParseFromString)
import HmmPrinter(mmPrintTheoremProof)
import System.Environment(getArgs)

main :: IO ()
main = do
	dbText <- getContents
	[theoremLabel] <- getArgs
	case mmParseFromString dbText of
		Left err -> putStrLn ("Parse error: " ++ err)
		Right (_, db) -> putStrLn $ mmPrintTheoremProof db theoremLabel
