#!/usr/bin/env bash

mvn clean source:jar javadoc:javadoc package -Dmaven.test.skip=false -D maven.javadoc.skip.true
