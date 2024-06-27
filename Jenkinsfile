pipeline {
    agent any
    
    parameters {
        string(name: 'AWS_ACCOUNT_ID', description: 'AWS Account ID')
        string(name: 'BUCKET_NAME', description: 'S3 Bucket Name')
        string(name: 'REPORT_BUCKET_NAME', description: 'S3 Report Bucket Name')
        string(name: 'ROLE_NAME', description: 'IAM Role Name')
    }
    
    environment {
        AWS_ACCESS_KEY_ID = credentials('ACCOUNT_ACCESS_KEY')
        AWS_SECRET_ACCESS_KEY = credentials('ACCOUNT_SECRET_KEY')
    }
    
    stages {
        stage('Clone Repository') {
            steps {
                git branch: 'main', url: 'https://github.com/belal-b-ali/jenkins-BO.git'
            }
        }
        stage('install req') {
            steps {
                sh '''#!/bin/bash
                    python3 -m venv venv
                    source venv/bin/activate
                    pip install boto3
                '''
            }
        }
        stage('Run Python Script') {
            steps {
                script {
                    sh '''#!/bin/bash
                        source venv/bin/activate
                        export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
                        export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
                        python3 -m main --aws_account_id=${AWS_ACCOUNT_ID} --bucket=${BUCKET} --report_bucket=${REPORT_BUCKET} --role_name=${ROLE_NAME}
                    '''
                }
            }
        }
    }
}
