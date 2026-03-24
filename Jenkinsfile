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
        
        stage('SonarQube - Analyse') {
    steps {
        withSonarQubeEnv('sonarqube') {
            sh '''
                docker run --rm \
                --network host \
                -e SONAR_HOST_URL=http://localhost:9000 \
                -e SONAR_TOKEN=$SONAR_AUTH_TOKEN \
                -v $(pwd):/usr/src \
                sonarsource/sonar-scanner-cli \
                -Dsonar.projectKey=mon-api-vuln \
                -Dsonar.sources=/usr/src \
                -Dsonar.inclusions=sqli/**/*.py,config/**/*.py \
                -Dsonar.language=py \
                -Dsonar.python.version=3
            '''
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
                sh '''
                    docker run --rm \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    aquasec/trivy image \
                    --exit-code 1 \
                    --severity CRITICAL \
                    umissa/mon-api-vuln
                '''
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

    post {
        failure {
            echo '❌ Pipeline échoué - Failles CRITICAL détectées ou erreur !'
        }
        success {
            echo '✅ Pipeline réussi - Aucune faille CRITICAL !'
        }
    }
}