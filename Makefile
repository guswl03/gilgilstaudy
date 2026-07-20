dall: sum-nbo

sum-nbo: sum-nbo.cpp
	g++ -o sum-nbo sum-nbo.cpp

clean:
	rm -f sum-nbo
