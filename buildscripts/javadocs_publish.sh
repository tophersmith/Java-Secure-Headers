#!/bin/bash

echo -e "repo: $TRAVIS_REPO_SLUG"
echo -e "ver: $TRAVIS_JDK_VERSION"
echo -e "bra: $TRAVIS_BRANCH"
echo -e "home: $HOME"

if [ "$TRAVIS_REPO_SLUG" == "tophersmith/Java-Secure-Headers" ] && [ "$TRAVIS_JDK_VERSION" == "oraclejdk8" ] && [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_BRANCH" == "master" ]; then
  echo -e "Creating javadoc"
  
  mvn -f security-headers/pom.xml javadoc:javadoc
  
  echo -e "Publishing javadoc..."

  cp -R security-headers/target/site/apidocs $HOME/javadoc-latest
  echo -e "Copied javadocs"
  
  cd $HOME
  git config --global user.email "travis@travis-ci.org"
  git config --global user.name "travis-ci"
  git clone --quiet --branch=gh-pages https://${GH_TOKEN}@github.com/tophersmith/Java-Secure-Headers gh-pages > /dev/null
  echo -e "Cloned gh-pages"
  
  cd gh-pages
  git rm -rf ./javadoc
  cp -Rf $HOME/javadoc-latest ./javadoc
  git add -f .
  git commit -m "Latest javadoc on successful travis build $TRAVIS_BUILD_NUMBER auto-pushed to gh-pages"
  git push -fq origin gh-pages > /dev/null
  echo -e "Published Javadoc to gh-pages.\n"
  
  fi
  
  
  