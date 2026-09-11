PAPER  = main
TEX    = $(wildcard *.tex table/*.tex)
BIB    = paper.bib
FIGS   = $(wildcard figs/*.pdf figs/*.png)

# FSE 2027: 18 pages text+figures (appendices included) + 4 pages references.

.PHONY: all clean pages spell archive

all: $(PAPER).pdf

$(PAPER).pdf: $(TEX) $(BIB) $(FIGS) acmart.cls ACM-Reference-Format.bst
	pdflatex -synctex=1 -interaction=nonstopmode $(PAPER)
	bibtex $(PAPER)
	pdflatex -synctex=1 -interaction=nonstopmode $(PAPER)
	pdflatex -synctex=1 -interaction=nonstopmode $(PAPER)
	@./pagecheck.sh $(PAPER).pdf

pages: $(PAPER).pdf
	@./pagecheck.sh $(PAPER).pdf

clean:
	rm -f *.aux *.bbl *.blg *.brf *.log *.out *.toc
	rm -f *-converted-to.pdf
	rm -f $(PAPER).pdf $(PAPER).synctex.gz

spell:
	ispell *.tex

archive:
	git archive --format=zip --prefix=dispatch/ HEAD -o dispatch.zip
