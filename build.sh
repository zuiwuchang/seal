#!/usr/bin/env bash

set -e

BashDir=$(cd "$(dirname $BASH_SOURCE)" && pwd)
eval $(cat "$BashDir/script/conf.sh")
if [[ "$Command" == "" ]];then
    Command="$0"
fi

function help(){
    echo "build script"
    echo
    echo "Usage:"
    echo "  $0 [flags]"
    echo "  $0 [command]"
    echo
    echo "Available Commands:"
    echo "  help              help for $0"
    echo "  clear             clear output"
    echo "  go                go build helper"
    echo "  pack              pack release"
    echo "  run               run project"
    echo "  docker            docker build helper"
    echo
    echo "Flags:"
    echo "  -h, --help          help for $0"
}

case "$1" in
    help|-h|--help)
        help
    ;;
    clear)
        shift
        export Command="$0 clear"
        "$BashDir/script/clear.sh" "$@"
    ;;
    pack)
        shift
        export Command="$0 pack"
        "$BashDir/script/pack.sh" "$@"
    ;;
    go)
        shift
        export Command="$0 go"
        "$BashDir/script/go.sh" "$@"
    ;;
    run)
        shift
        cd "$BashDir/bin"
        ./seal ca \
            --pri root.pri --pub root.pub \
            -H SHA-256 -b 4096 \
            -C cn -S sichuan -L chengdu \
            -O cerberus -o it \
            -c "root ca" \
            -y
        du -b root.p*

        ./seal ca \
            -p root.pri \
            --pri ca0.pri --pub ca0.pub \
            -H SHA-256 -b 2048 \
            -C cn -S sichuan -L chengdu \
            -O cerberus -o it \
            -c "root->ca0" \
            -y
        du -b ca0.p*

        ./seal ca \
            -p root.pri \
            --pri ca1.pri --pub ca1.pub \
            -H SHA-256 -b 2048 \
            -C cn -S sichuan -L chengdu \
            -O cerberus -o it \
            -c "root->ca1" \
            -y
        du -b ca1.p*

        ./seal ca \
            -p ca0.pri \
            --pri caA.pri --pub caA.pub \
            -H SHA-256 -b 2048 \
            -C cn -S sichuan -L chengdu \
            -O cerberus -o it \
            -c "root->ca0->caA" \
            -y
        du -b caA.p*

        ./seal ca \
            -p ca1.pri \
            --pri caB.pri --pub caB.pub \
            -H SHA-256 -b 2048 \
            -C cn -S sichuan -L chengdu \
            -O cerberus -o it \
            -c "root->ca1->caB" \
            -y
        du -b caB.p*
        exit $?
    ;;
    docker)
        shift
        export Command="$0 docker"
        "$BashDir/script/docker.sh" "$@"
    ;;
    *)
        if [[ "$1" == "" ]];then
            help
        elif [[ "$1" == -* ]];then
            echo Error: unknown flag "$1" for "$0"
            echo "Run '$0 --help' for usage."
        else
            echo Error: unknown command "$1" for "$0"
            echo "Run '$0 --help' for usage."
        fi        
        exit 1
    ;;
esac