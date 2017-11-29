SRCDIR = src
OBJDIR = obj
BINDIR = bin
SRCS = $(wildcard $(SRCDIR)/*.cc)
OBJS = $(SRCS:$(SRCDIR)/%.cc=$(OBJDIR)/%.o)
CXX = g++
CXXFLAGS = -g -Wall -std=c++11
LDFLAGS = -lpthread
BUILDDIRS = $(OBJDIR) $(BINDIR)

default: build

build: create_dirs build_actual

build_actual: $(BINDIR)/migrateclient

$(BINDIR)/migrateclient: $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)

$(OBJS): $(OBJDIR)/%.o: $(SRCDIR)/%.cc
	$(CXX) -c -o $@ $< $(CXXFLAGS)

create_dirs:
	@mkdir -p $(BUILDDIRS)

.PHONY: clean

clean:
	rm -rf $(BINDIR)/migrateclient $(OBJS)
