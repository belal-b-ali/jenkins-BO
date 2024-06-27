pipeline {
    agent any0
    environment {
        // Define environment variables for AWS credentials
        AWS_ACCESS_KEY_ID = credentials('aws-access-key-id') // Replace with your credentials ID
        AWS_SECRET_ACCESS_KEY = credentials('aws-secret-access-key') // Replace with your credentials ID
    }
    stages {
        stage('Checkout') {
            steps {
                // Checkout the source code from the repository
                checkout scm
            }
        }
        stage('Install Dependencies') {
            steps {
                // Install the required Python dependencies
                sh 'pip install boto3'
            }
        }
        stage('Run Script') {
            steps {
                // Run the Python script with the necessary arguments
                sh """
                python your_script.py \
                    --source_aws_access_key_id $AWS_ACCESS_KEY_ID \
                    --source_aws_secret_access_key $AWS_SECRET_ACCESS_KEY \
                    --source_aws_account_id your-source-account-id \
                    --source_bucket your-source-bucket-name \
                    --report_bucket your-report-bucket-name \
                    --role_name your-role-name
                """
            }
        }
    }
    post {
        always {
            // Clean up after build
            cleanWs()
        }
    }
}
