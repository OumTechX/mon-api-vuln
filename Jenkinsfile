pipeline {
    agent any
    
    environment {
        DOCKER_HUB_CREDENTIALS = credentials('docker-hub-credentials')
    }
    
    stages {
        
        stage('Récupérer le code') {
            steps {
                echo 'Récupération du code depuis GitHub...'
            }
        }
     stage('SonarQube Analysis') {
 steps {
   script {
     docker.image('sonarsource/sonar-scanner-cli').inside('-v $WORKSPACE:/usr/src') {
       sh '''
       sonar-scanner \
       -Dsonar.projectKey=mon-api-vuln \
       -Dsonar.sources=sqli \
       -Dsonar.host.url=http://sonarqube:9000 \
       -Dsonar.login=$SONAR_TOKEN
       '''
     }
   }
 }
}
}
        
        stage('Builder Docker') {
            steps {
                echo 'Construction de l image Docker...'
                sh 'docker build -t umissa/mon-api-vuln .'
            }
        }
        
        stage('Scanner avec Trivy') {
            steps {
                echo 'Scan de sécurité avec Trivy...'
                sh 'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --exit-code 0 --severity HIGH,CRITICAL umissa/mon-api-vuln'
            }
        }
        
        stage('Login Docker Hub') {
            steps {
                sh 'echo $DOCKER_HUB_CREDENTIALS_PSW | docker login -u $DOCKER_HUB_CREDENTIALS_USR --password-stdin'
            }
        }
        
        stage('Pousser sur Docker Hub') {
            steps {
                echo 'Push sur Docker Hub...'
                sh 'docker push umissa/mon-api-vuln'
            }
        }
        
        stage('Déployer sur Kubernetes') {
            steps {
                echo 'Déploiement sur Kubernetes...'
                sh 'kubectl apply -f webapp.yaml'
            }
        }
    }
}