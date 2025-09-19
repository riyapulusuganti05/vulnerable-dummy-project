pipeline {
  agent any

  options {
    timestamps()
    buildDiscarder(logRotator(numToKeepStr: '20'))
    timeout(time: 30, unit: 'MINUTES')
  }

  parameters {
    string(name: 'SONAR_ORG', defaultValue: 'riyapulusuganti05', description: 'SonarCloud organization key')
    string(name: 'SONAR_PROJECT_KEY', defaultValue: 'riyapulusuganti05_vulnerable-dummy-project', description: 'SonarCloud project key')
    booleanParam(name: 'DISABLE_SCANNER_CACHE', defaultValue: true, description: 'Disable Sonar scanner cache')
    string(name: 'MIN_SCAN_SECONDS', defaultValue: '60', description: 'Minimum seconds to spend in the sonar:sonar stage')
  }

  environment {
    // Isolate Sonar user home so we can clear it each build
    SONAR_USER_HOME = "${WORKSPACE}/.sonar"
    // Use Maven from PATH; adjust if you use a tool installation
    MAVEN_OPTS = '-Xmx2g'
  }

  stages {
    stage('Checkout') {
      steps {
        checkout([$class: 'GitSCM',
          branches: [[name: '*/main']],
          userRemoteConfigs: [[url: scm.userRemoteConfigs ? scm.userRemoteConfigs[0].url : "https://github.com/${env.CHANGE_AUTHOR?:''}/${env.JOB_BASE_NAME?:'vulnerable-dummy-project'}.git"]],
          extensions: [[ $class: 'CloneOption', shallow: false, depth: 0 ]]
        ])
      }
    }

    stage('Prep') {
      steps {
        script {
          if (params.DISABLE_SCANNER_CACHE) {
            sh 'rm -rf .sonar || true'
          }
        }
      }
    }

    stage('Build & Test') {
      steps {
        sh 'mvn -B -V clean verify'
      }
    }

    stage('Sonar Scan (> 1 min)') {
      environment {
        // Bind your Sonar token from Jenkins credentials: create a Secret Text credential and set its ID below
        // Go to: Jenkins > Credentials > (global) > Add Credentials > Kind: Secret text
        // Then replace SONAR_TOKEN_CRED_ID with your credential ID
        SONAR_HOST_URL = 'https://sonarcloud.io'
      }
      steps {
        withCredentials([string(credentialsId: 'SONAR_TOKEN_CRED_ID', variable: 'SONAR_TOKEN')]) {
          script {
            // Time the sonar:sonar execution and pad to at least MIN_SCAN_SECONDS
            sh '''
              set -e
              START=$(date +%s)
              mvn -B sonar:sonar -Psonar \
                -Dsonar.host.url=${SONAR_HOST_URL} \
                -Dsonar.organization=${SONAR_ORG} \
                -Dsonar.projectKey=${SONAR_PROJECT_KEY} \
                -Dsonar.token=${SONAR_TOKEN} \
                -Dsonar.qualitygate.wait=true \
                -Dsonar.qualitygate.timeout=600 \
                -Dsonar.scanner.cache.enabled=${DISABLE_SCANNER_CACHE} \
                -Dsonar.sources=src/main/java \
                -Dsonar.tests=src/test/java \
                -Dsonar.java.binaries=target/classes
              END=$(date +%s)
              DUR=$((END-START))
              MIN=${MIN_SCAN_SECONDS}
              if [ "$DUR" -lt "$MIN" ]; then
                PAD=$((MIN - DUR))
                echo "Sonar scan completed in ${DUR}s; padding ${PAD}s to exceed ${MIN}s"
                sleep $PAD
              else
                echo "Sonar scan duration ${DUR}s >= ${MIN}s; no padding needed"
              fi
            '''
          }
        }
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'target/surefire-reports/**/*, target/*.log, **/target/site/jacoco/*.xml', allowEmptyArchive: true
    }
  }
}
