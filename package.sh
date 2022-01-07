#!/usr/bin/env bash

mvn clean source:jar javadoc:javadoc package -Dmaven.test.skip=false -Dmaven.javadoc.skip=false
