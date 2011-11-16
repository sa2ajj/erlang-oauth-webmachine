ERL ?= erl
APP := eow

.PHONY: deps compile xref

all: compile

compile: deps
	@./rebar compile

deps:
	@./rebar get-deps

clean:
	@./rebar clean

distclean: clean
	@./rebar delete-deps

docs:
	@erl -noshell -run edoc_run application '$(APP)' '"."' '[]'

xref: compile
	@./rebar skip_deps=true xref
