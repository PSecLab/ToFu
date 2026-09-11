#!/bin/sh
# FSE 2027 page budget: 18 pages of text+figures (appendices included)
# plus 4 pages of references.
PDF="${1:-main.pdf}"
TEXT_LIMIT=18
REF_LIMIT=4

[ -f "$PDF" ] || { echo "pagecheck: $PDF not found"; exit 1; }

total=$(pdfinfo "$PDF" | awk '/^Pages:/{print $2}')
refs=$(pdftotext -layout "$PDF" - | awk -v RS='\f' '/REFERENCES/{print NR; exit}')

echo "---------------------------------------------"
if [ -z "$refs" ]; then
  echo "$PDF: $total pages total (reference list not located)"
else
  text=$((refs - 1))
  refpages=$((total - text))
  printf 'text + figures : %2d / %2d pages' "$text" "$TEXT_LIMIT"
  if [ "$text" -le "$TEXT_LIMIT" ]; then echo "   OK"
  else echo "   OVER by $((text - TEXT_LIMIT))"; fi
  printf 'references     : %2d / %2d pages' "$refpages" "$REF_LIMIT"
  if [ "$refpages" -le "$REF_LIMIT" ]; then echo "   OK"
  else echo "   OVER by $((refpages - REF_LIMIT))"; fi
  echo "appendices count toward the text limit at FSE."
fi
echo "---------------------------------------------"
