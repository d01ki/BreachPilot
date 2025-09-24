#!/bin/bash

echo "🔧 BreachPilot Dependency Fix Script"
echo "===================================="

# Function to check if we're in a virtual environment
check_venv() {
    if [[ -n "$VIRTUAL_ENV" ]]; then
        echo "✅ Virtual environment active: $VIRTUAL_ENV"
        return 0
    else
        echo "❌ No virtual environment detected"
        echo "Please activate your virtual environment first:"
        echo "  source venv/bin/activate"
        exit 1
    fi
}

# Function to fix CFFI version mismatch
fix_cffi_mismatch() {
    echo ""
    echo "🔄 Fixing CFFI version mismatch..."
    
    # Uninstall potentially conflicting packages
    echo "📦 Uninstalling conflicting packages..."
    pip uninstall -y cffi pycryptodome cryptodome impacket
    
    # Clear pip cache
    echo "🧹 Clearing pip cache..."
    pip cache purge
    
    # Install packages in specific order
    echo "📦 Installing CFFI with compatible version..."
    pip install "cffi>=1.16.0,<2.0.0"
    
    echo "📦 Installing Cryptodome..."
    pip install "pycryptodome>=3.19.0"
    
    echo "📦 Installing impacket..."
    pip install "impacket>=0.12.0"
    
    # Install other requirements
    echo "📦 Installing remaining requirements..."
    pip install -r requirements.txt
    
    echo "✅ Dependency fix completed"
}

# Function to test imports
test_imports() {
    echo ""
    echo "🧪 Testing critical imports..."
    
    python3 -c "
import sys
try:
    import cffi
    print(f'✅ CFFI version: {cffi.__version__}')
    
    # Test cffi backend compatibility
    import _cffi_backend
    backend_version = getattr(_cffi_backend, '__version__', 'unknown')
    print(f'✅ CFFI backend version: {backend_version}')
    
    if cffi.__version__ != backend_version and backend_version != 'unknown':
        print(f'⚠️  Version mismatch detected but continuing...')
    else:
        print('✅ CFFI versions compatible')
        
except ImportError as e:
    print(f'❌ CFFI import failed: {e}')
    sys.exit(1)
except Exception as e:
    print(f'❌ CFFI compatibility issue: {e}')
    sys.exit(1)

try:
    from Cryptodome.Cipher import ARC4
    print('✅ Cryptodome import successful')
except ImportError as e:
    print(f'❌ Cryptodome import failed: {e}')
    sys.exit(1)
except Exception as e:
    print(f'❌ Cryptodome compatibility issue: {e}')
    sys.exit(1)

try:
    import impacket
    print(f'✅ Impacket version: {getattr(impacket, \"__version__\", \"unknown\")}')
    
    # Test impacket import that was failing
    from impacket.dcerpc.v5 import nrpc, epm
    print('✅ Impacket critical modules import successful')
    
except ImportError as e:
    print(f'❌ Impacket import failed: {e}')
    sys.exit(1)
except Exception as e:
    print(f'❌ Impacket compatibility issue: {e}')
    sys.exit(1)

print('🎉 All critical imports successful!')
"
    
    if [ $? -eq 0 ]; then
        echo "✅ Import tests passed"
        return 0
    else
        echo "❌ Import tests failed"
        return 1
    fi
}

# Main execution
main() {
    echo "Starting BreachPilot dependency fix..."
    
    # Check virtual environment
    check_venv
    
    # Fix dependencies
    fix_cffi_mismatch
    
    # Test imports
    if test_imports; then
        echo ""
        echo "🎉 Dependency fix completed successfully!"
        echo "You can now run BreachPilot without CFFI version errors."
        echo ""
        echo "To start BreachPilot:"
        echo "  python app.py"
    else
        echo ""
        echo "❌ Dependency fix failed. Please check the error messages above."
        echo "You may need to:"
        echo "1. Delete your virtual environment and recreate it"
        echo "2. Check for system-wide Python package conflicts"
        echo "3. Use a Docker environment for isolation"
        exit 1
    fi
}

# Run main function
main
