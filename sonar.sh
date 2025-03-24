#!/bin/bash

echo "🚀 Setting higher ulimit..."
ulimit -n 65536

echo "📦 Compiling project..."
mvn clean compile

echo "🔍 Running SonarScanner..."
sonar-scanner

