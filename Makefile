all:
	@echo "Make what homie?"

install:
	python setup.py install

clean:
	find . -iname '*.pyc' -type f -exec rm -f \{\} \;
	python setup.py clean
	rm -fr build
